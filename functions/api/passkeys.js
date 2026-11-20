
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse
} from "@simplewebauthn/server";

const RP_ID = "bergholzbandattendance.com";
const RP_NAME = "Bergholz Band Attendance";
const ORIGIN = "https://bergholzbandattendance.com";
const TEN_MINUTES = 10 * 60 * 1000;
const SESSION_LENGTH = 30 * 24 * 60 * 60 * 1000;

function json(data, status = 200, headers = {}) {
  return Response.json(data, {
    status,
    headers: {
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function cookie(request, name) {
  return request.headers.get("Cookie")
    ?.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith(name + "="))
    ?.slice(name.length + 1);
}

function randomToken() {
  return Array.from(crypto.getRandomValues(new Uint8Array(32)))
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

async function sha(value) {
  const bytes = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value)
  );
  return Array.from(new Uint8Array(bytes))
    .map(x => x.toString(16).padStart(2, "0"))
    .join("");
}

function toBase64URL(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function fromBase64URL(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized.padEnd(
    Math.ceil(normalized.length / 4) * 4,
    "="
  ));
  return Uint8Array.from(binary, c => c.charCodeAt(0));
}

async function currentUser(request, env) {
  const token = cookie(request, "band_session");
  if (!token) return null;

  return env.DB.prepare(`
    SELECT m.*
    FROM sessions s
    JOIN members m ON m.id = s.member_id
    WHERE s.token_hash = ?
      AND s.expires_at > ?
      AND m.active = 1
  `).bind(await sha(token), Date.now()).first();
}

function challengeCookie(challenge) {
  return `passkey_challenge=${challenge}; HttpOnly; Secure; SameSite=Strict; Path=/api/passkeys; Max-Age=600`;
}

const clearChallengeCookie =
  "passkey_challenge=; HttpOnly; Secure; SameSite=Strict; Path=/api/passkeys; Max-Age=0";

async function saveChallenge(env, challenge, memberId, purpose) {
  await env.DB.prepare(
    "DELETE FROM passkey_challenges WHERE expires_at < ?"
  ).bind(Date.now()).run();

  await env.DB.prepare(`
    INSERT INTO passkey_challenges
      (challenge, member_id, purpose, expires_at)
    VALUES (?, ?, ?, ?)
  `).bind(
    challenge,
    memberId,
    purpose,
    Date.now() + TEN_MINUTES
  ).run();
}

async function consumeChallenge(request, env, purpose) {
  const challenge = cookie(request, "passkey_challenge");
  if (!challenge) return null;

  const result = await env.DB.prepare(`
    DELETE FROM passkey_challenges
    WHERE challenge = ?
      AND purpose = ?
      AND expires_at > ?
    RETURNING *
  `).bind(challenge, purpose, Date.now()).first();

  return result || null;
}

async function createSession(env, memberId) {
  const token = randomToken();

  await env.DB.prepare(`
    INSERT INTO sessions
      (token_hash, member_id, expires_at)
    VALUES (?, ?, ?)
  `).bind(
    await sha(token),
    memberId,
    Date.now() + SESSION_LENGTH
  ).run();

  return `band_session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}

export async function onRequest({ request, env }) {
  try {
    if (!env.DB) {
      return json({ error: "Database unavailable" }, 503);
    }

    if (request.method !== "POST") {
      return json({ error: "Method not allowed" }, 405);
    }

    const url = new URL(request.url);

    if (url.origin !== ORIGIN ||
        request.headers.get("Origin") !== ORIGIN) {
      return json({ error: "Invalid request origin" }, 403);
    }

    const action = url.searchParams.get("action");
    const data = await request.json().catch(() => null);

    if (!data || typeof data !== "object") {
      return json({ error: "Invalid request data" }, 400);
    }

    // Passkey management: authenticated members only.
    if (action === "list") {
      const user = await currentUser(request, env);

      if (!user) {
        return json({ error: "Sign in required" }, 401);
      }

      const result = await env.DB.prepare(`
        SELECT id, device_name, created_at, last_used_at
        FROM member_passkeys
        WHERE member_id = ?
        ORDER BY created_at DESC, id DESC
      `).bind(user.id).all();

      return json({ passkeys: result.results });
    }

    if (action === "rename") {
      const user = await currentUser(request, env);

      if (!user) {
        return json({ error: "Sign in required" }, 401);
      }

      const id = Number(data.id);
      const name = String(data.device_name || "").trim();

      if (!Number.isSafeInteger(id) || id < 1 ||
          !name || name.length > 60) {
        return json({ error: "Invalid passkey details" }, 400);
      }

      const result = await env.DB.prepare(`
        UPDATE member_passkeys
        SET device_name = ?
        WHERE id = ? AND member_id = ?
      `).bind(name, id, user.id).run();

      if (result.meta.changes !== 1) {
        return json({ error: "Passkey not found" }, 404);
      }

      return json({ ok: true });
    }

    // Begin removal: verify identity with an existing passkey.
    if (action === "remove-options") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "Sign in required" }, 401);

      const id = Number(data.id);
      if (!Number.isSafeInteger(id) || id < 1) {
        return json({ error: "Invalid passkey ID" }, 400);
      }

      const existing = await env.DB.prepare(`
        SELECT id, credential_id
        FROM member_passkeys
        WHERE member_id = ?
      `).bind(user.id).all();

      if (!existing.results.some(p => p.id === id)) {
        return json({ error: "Passkey not found" }, 404);
      }

      const options = await generateAuthenticationOptions({
        rpID: RP_ID,
        userVerification: "required",
        allowCredentials: existing.results.map(p => ({
          id: p.credential_id
        }))
      });

      await saveChallenge(
        env, options.challenge, user.id, "authentication"
      );

      return json({ options }, 200, {
        "Set-Cookie": challengeCookie(options.challenge)
      });
    }

    // Finish removal only after verifying the signed-in member.
    if (action === "remove-verify") {
      const user = await currentUser(request, env);
      if (!user) return json({ error: "Sign in required" }, 401);

      const id = Number(data.id);
      if (!Number.isSafeInteger(id) || id < 1) {
        return json({ error: "Invalid passkey ID" }, 400);
      }

      const saved = await consumeChallenge(
        request, env, "authentication"
      );

      if (!saved || saved.member_id !== user.id) {
        return json({ error: "Verification expired" }, 400, {
          "Set-Cookie": clearChallengeCookie
        });
      }

      const stored = await env.DB.prepare(`
        SELECT *
        FROM member_passkeys
        WHERE credential_id = ? AND member_id = ?
      `).bind(String(data.response?.id || ""), user.id).first();

      if (!stored) {
        return json({ error: "Passkey not recognized" }, 401);
      }

      const verified = await verifyAuthenticationResponse({
        response: data.response,
        expectedChallenge: saved.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true,
        credential: {
          id: stored.credential_id,
          publicKey: fromBase64URL(stored.public_key),
          counter: stored.counter
        }
      });

      if (!verified.verified) {
        return json({ error: "Verification failed" }, 401);
      }

      await env.DB.prepare(`
        UPDATE member_passkeys
        SET counter = ?, last_used_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        verified.authenticationInfo.newCounter, stored.id
      ).run();

      const result = await env.DB.prepare(`
        DELETE FROM member_passkeys
        WHERE id = ? AND member_id = ?
      `).bind(id, user.id).run();

      if (result.meta.changes !== 1) {
        return json({ error: "Passkey not found" }, 404);
      }

      return json({ ok: true }, 200, {
        "Set-Cookie": clearChallengeCookie
      });
    }

    // 1. Start registration: existing login required.
    if (action === "register-options") {
      const user = await currentUser(request, env);
      if (!user) {
        return json({ error: "Sign in required" }, 401);
      }

      const existing = await env.DB.prepare(`
        SELECT credential_id
        FROM member_passkeys
        WHERE member_id = ?
      `).bind(user.id).all();

      const options = await generateRegistrationOptions({
        rpName: RP_NAME,
        rpID: RP_ID,
        userID: new TextEncoder().encode(String(user.id)),
        userName: user.email,
        userDisplayName: user.display_name,
        attestationType: "none",
        authenticatorSelection: {
          residentKey: "required",
          userVerification: "required"
        },
        excludeCredentials: existing.results.map(row => ({
          id: row.credential_id
        }))
      });

      await saveChallenge(
        env,
        options.challenge,
        user.id,
        "registration"
      );

      return json(
        { options },
        200,
        { "Set-Cookie": challengeCookie(options.challenge) }
      );
    }

    // 2. Complete registration.
    if (action === "register-verify") {
      const user = await currentUser(request, env);
      if (!user) {
        return json({ error: "Sign in required" }, 401);
      }

      const saved = await consumeChallenge(
        request,
        env,
        "registration"
      );

      if (!saved || saved.member_id !== user.id) {
        return json({ error: "Registration expired" }, 400, {
          "Set-Cookie": clearChallengeCookie
        });
      }

      const result = await verifyRegistrationResponse({
        response: data,
        expectedChallenge: saved.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true
      });

      if (!result.verified || !result.registrationInfo) {
        return json({ error: "Passkey verification failed" }, 400);
      }

      const { credential } = result.registrationInfo;

      await env.DB.prepare(`
        INSERT INTO member_passkeys
          (member_id, credential_id, public_key, counter, device_name)
        VALUES (?, ?, ?, ?, ?)
      `).bind(
        user.id,
        credential.id,
        toBase64URL(credential.publicKey),
        credential.counter,
        "Passkey"
      ).run();

      return json(
        { ok: true, message: "Passkey registered successfully" },
        200,
        { "Set-Cookie": clearChallengeCookie }
      );
    }

    // 3. Start passkey login.
    if (action === "login-options") {
      const options = await generateAuthenticationOptions({
        rpID: RP_ID,
        userVerification: "required"
      });

      await saveChallenge(
        env,
        options.challenge,
        null,
        "authentication"
      );

      return json(
        { options },
        200,
        { "Set-Cookie": challengeCookie(options.challenge) }
      );
    }

    // 4. Complete passkey login.
    if (action === "login-verify") {
      const saved = await consumeChallenge(
        request,
        env,
        "authentication"
      );

      if (!saved) {
        return json({ error: "Login challenge expired" }, 400, {
          "Set-Cookie": clearChallengeCookie
        });
      }

      const credentialId = String(data.id || "");

      const stored = await env.DB.prepare(`
        SELECT p.*, m.active
        FROM member_passkeys p
        JOIN members m ON m.id = p.member_id
        WHERE p.credential_id = ?
      `).bind(credentialId).first();

      if (!stored || stored.active !== 1) {
        return json({ error: "Passkey not recognized" }, 401, {
          "Set-Cookie": clearChallengeCookie
        });
      }

      const result = await verifyAuthenticationResponse({
        response: data,
        expectedChallenge: saved.challenge,
        expectedOrigin: ORIGIN,
        expectedRPID: RP_ID,
        requireUserVerification: true,
        credential: {
          id: stored.credential_id,
          publicKey: fromBase64URL(stored.public_key),
          counter: stored.counter
        }
      });

      if (!result.verified) {
        return json({ error: "Passkey verification failed" }, 401);
      }

      await env.DB.prepare(`
        UPDATE member_passkeys
        SET counter = ?, last_used_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(
        result.authenticationInfo.newCounter,
        stored.id
      ).run();

      const sessionCookie = await createSession(
        env,
        stored.member_id
      );

      const headers = new Headers({
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
      });

      headers.append("Set-Cookie", sessionCookie);
      headers.append("Set-Cookie", clearChallengeCookie);

      return new Response(
        JSON.stringify({ ok: true }),
        { status: 200, headers }
      );
    }

    return json({ error: "Unknown passkey action" }, 404);

  } catch (error) {
    console.error("Passkey API error", error);
    return json({ error: "Passkey request failed" }, 500);
  }
}
