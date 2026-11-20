
const json = (data, status = 200) =>
  Response.json(data, {
    status,
    headers: { "Cache-Control": "no-store" }
  });

const sha = async value =>
  Array.from(
    new Uint8Array(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(value)
      )
    )
  ).map(x => x.toString(16).padStart(2, "0")).join("");

const isOwner = u =>
  u?.email?.toLowerCase() === "brandenstoll@gmail.com";

const isAdmin = u =>
  !!u && (isOwner(u) || u.role === "admin");

const isLeader = u =>
  !!u && (isAdmin(u) || u.role === "leader");

const categories = [
  "Technical Issue",
  "Attendance Correction",
  "Calendar / Event Change",
  "Member Information Update",
  "Suggestion / General Question"
];

async function currentUser(request, env) {
  const token = request.headers.get("Cookie")
    ?.split(";")
    .map(x => x.trim())
    .find(x => x.startsWith("band_session="))
    ?.slice("band_session=".length);

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

function canView(user, record) {
  if (isAdmin(user) || record.member_id === user.id) {
    return true;
  }

  return user.role === "leader" &&
    user.section_id != null &&
    record.section_id === user.section_id;
}

function canManage(user, record) {
  if (isAdmin(user)) return true;

  return user.role === "leader" &&
    user.section_id != null &&
    record.section_id === user.section_id &&
    [
      "Attendance Correction",
      "Member Information Update",
      "Suggestion / General Question"
    ].includes(record.request_type);
}

async function sendNotification(env, record, recipients) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM) {
    console.error("Support email is not configured");
    return;
  }

  const emails = [...new Set(
    recipients.filter(Boolean).map(x => x.toLowerCase())
  )];

  if (!emails.length) return;

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      from: env.MAIL_FROM,
      to: emails,
      subject: `Bergholz Band Request ${record.tracking_number}`,
      text: [
        `New request: ${record.tracking_number}`,
        `Category: ${record.request_type}`,
        `Submitted by: ${record.member_name}`,
        `Event: ${record.event_reference || "Not specified"}`,
        "",
        record.description,
        "",
        "Sign in to the Bergholz Band Attendance Portal",
        "to review and manage this request."
      ].join("\n")
    })
  });

  if (!response.ok) {
    console.error("Support email failed", response.status);
  }
}

export async function onRequest({ request, env }) {
  try {
    if (!env.DB) {
      return json({ error: "Database unavailable" }, 503);
    }

    const method = request.method;

    if (!["GET", "POST", "PATCH"].includes(method)) {
      return json({ error: "Method not allowed" }, 405);
    }

    if (method !== "GET") {
      const origin = request.headers.get("Origin");
      if (origin && origin !== new URL(request.url).origin) {
        return json({ error: "Invalid origin" }, 403);
      }
    }

    const user = await currentUser(request, env);

    if (!user) {
      return json({ error: "Sign in required" }, 401);
    }

    // LIST REQUESTS
    if (method === "GET") {
      let query;
      let args;

      if (isAdmin(user)) {
        query = `
          SELECT * FROM support_requests
          ORDER BY created_at DESC, id DESC
          LIMIT 500
        `;
        args = [];
      } else if (user.role === "leader") {
        query = `
          SELECT * FROM support_requests
          WHERE member_id = ? OR section_id = ?
          ORDER BY created_at DESC, id DESC
          LIMIT 500
        `;
        args = [user.id, user.section_id];
      } else {
        query = `
          SELECT * FROM support_requests
          WHERE member_id = ?
          ORDER BY created_at DESC, id DESC
          LIMIT 500
        `;
        args = [user.id];
      }

      const result = await env.DB.prepare(query)
        .bind(...args).all();

      return json({ requests: result.results });
    }

    let data;
    try {
      data = await request.json();
    } catch {
      return json({ error: "Invalid JSON" }, 400);
    }

    // SUBMIT REQUEST
    if (method === "POST") {
      const category = String(data?.request_type || "");
      const description = String(data?.description || "").trim();
      const event = String(data?.event_reference || "").trim();

      if (
        !categories.includes(category) ||
        !description ||
        description.length > 4000 ||
        event.length > 200
      ) {
        return json({ error: "Invalid request details" }, 400);
      }

      const section = user.section_confirmed === 0
        ? null
        : user.section_id;

      const result = await env.DB.prepare(`
        INSERT INTO support_requests
        (
          member_id, member_name, member_email,
          request_type, section_id,
          event_reference, description
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `).bind(
        user.id,
        user.display_name,
        user.email,
        category,
        section,
        event || null,
        description
      ).run();

      const id = result.meta.last_row_id;
      const tracking = `BB-${String(id).padStart(6, "0")}`;

      await env.DB.prepare(`
        UPDATE support_requests
        SET tracking_number = ?
        WHERE id = ?
      `).bind(tracking, id).run();

      await env.DB.prepare(`
        INSERT INTO support_request_history
        (request_id, actor_member_id, action, details)
        VALUES (?, ?, ?, ?)
      `).bind(id, user.id, "Created", category).run();

      const record = await env.DB.prepare(`
        SELECT * FROM support_requests WHERE id = ?
      `).bind(id).first();

      const leaders = await env.DB.prepare(`
        SELECT email FROM members
        WHERE active = 1
          AND (
            role = 'admin'
            OR (
              role = 'leader'
              AND section_id = ?
              AND ? IN (
                'Attendance Correction',
                'Member Information Update',
                'Suggestion / General Question'
              )
            )
          )
      `).bind(section, category).all();

      try {
        await sendNotification(env, record, [
          "brandenstoll@gmail.com",
          ...leaders.results.map(x => x.email)
        ]);
      } catch (error) {
        console.error("Notification error", error);
      }

      return json({ ok: true, request: record }, 201);
    }

    // UPDATE REQUEST
    const id = Number(data?.id);

    if (!Number.isSafeInteger(id) || id < 1) {
      return json({ error: "Valid request ID required" }, 400);
    }

    const record = await env.DB.prepare(`
      SELECT * FROM support_requests WHERE id = ?
    `).bind(id).first();

    if (!record || !canView(user, record)) {
      return json({ error: "Request not found" }, 404);
    }

    if (!canManage(user, record)) {
      return json({ error: "Permission denied" }, 403);
    }

    const takeOwnership = data?.take_ownership === true;
    const status = data?.status;

    if (
      !takeOwnership &&
      !["New", "In Progress", "Resolved"].includes(status)
    ) {
      return json({ error: "Invalid status" }, 400);
    }

    if (takeOwnership) {
      if (
        record.assigned_to &&
        record.assigned_to !== user.id &&
        !isAdmin(user)
      ) {
        return json({
          error: "Request is already assigned to another leader"
        }, 409);
      }

      await env.DB.prepare(`
        UPDATE support_requests
        SET assigned_to = ?,
            status = CASE
              WHEN status = 'New' THEN 'In Progress'
              ELSE status
            END,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).bind(user.id, id).run();

    } else {
      await env.DB.prepare(`
        UPDATE support_requests
        SET status = ?,
            updated_at = CURRENT_TIMESTAMP,
            resolved_at = CASE
              WHEN ? = 'Resolved' THEN CURRENT_TIMESTAMP
              ELSE NULL
            END
        WHERE id = ?
      `).bind(status, status, id).run();
    }

    await env.DB.prepare(`
      INSERT INTO support_request_history
      (request_id, actor_member_id, action, details)
      VALUES (?, ?, ?, ?)
    `).bind(
      id,
      user.id,
      takeOwnership ? "Ownership taken" : "Status changed",
      takeOwnership ? user.display_name : status
    ).run();

    const updated = await env.DB.prepare(`
      SELECT * FROM support_requests WHERE id = ?
    `).bind(id).first();

    return json({ ok: true, request: updated });

  } catch (error) {
    console.error("Support API error", error);
    return json({ error: "Request failed" }, 500);
  }
}
