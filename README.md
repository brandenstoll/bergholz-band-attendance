# Bergholz German Band Attendance Portal

A Cloudflare Pages + D1 starter for baritone and tenor horn, structured for additional sections.

## Deploy
1. Create a new GitHub repository and upload `index.html`, `functions/`, `schema.sql`, and `seed.sql` (keep their paths).
2. Create a Cloudflare D1 database. Run `schema.sql`, then `seed.sql` in the D1 console.
3. Create a Cloudflare Pages project connected to that repository, using no build command and `/` as output directory (if Pages requires an output folder, move `index.html` to `public/index.html` and set output to `public`).
4. Bind D1 under **Settings → Functions → D1 database bindings** with variable name `DB`.
5. Configure secrets `AUTH_SECRET` (long random string) and `RESEND_API_KEY`; configure `MAIL_FROM` as an address on a verified sending domain in Resend.
6. Add approved members to D1, e.g. `INSERT INTO members(email,display_name,section_id,role) VALUES('leader@example.com','Section Leader',1,'leader');` Use actual member email addresses, not example addresses.
7. Test sign-in and attendance on the deployed site. Do not publish real member email addresses in GitHub.

## Security and deployment notes
- Only pre-approved emails can sign in. Codes expire in 10 minutes, with five verification attempts per code. Sessions last 30 days and use HttpOnly Secure cookies.
- The initial implementation needs production hardening before broad public use: rate-limit sign-in requests using Cloudflare WAF/rate limiting; configure abuse protection, email delivery monitoring, and backup/restore.
- The member dashboard currently lists responses received; it does not list members who have not responded. An admin member-management UI, event editing, per-section event assignments, and reminders are planned extensions.
- Future expansion: add sections and memberships; introduce event-section assignments and multi-section leaders before adding new sections. Current events are global, and a member belongs to one section.
- No rehearsal times or locations were supplied, so none were invented. December 1, 2026 is Tuesday in the supplied schedule.
