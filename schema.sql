CREATE TABLE IF NOT EXISTS sections (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE);
CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY, email TEXT NOT NULL UNIQUE COLLATE NOCASE, display_name TEXT NOT NULL, section_id INTEGER NOT NULL REFERENCES sections(id), role TEXT NOT NULL DEFAULT 'member' CHECK(role IN ('member','leader','admin')), active INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, title TEXT NOT NULL, event_type TEXT NOT NULL CHECK(event_type IN ('rehearsal','performance')), event_date TEXT NOT NULL, start_time TEXT, location TEXT, notes TEXT, status TEXT NOT NULL DEFAULT 'scheduled' CHECK(status IN ('scheduled','cancelled')));
CREATE TABLE IF NOT EXISTS attendance (event_id INTEGER NOT NULL REFERENCES events(id), member_id INTEGER NOT NULL REFERENCES members(id), response TEXT NOT NULL CHECK(response IN ('yes','no','maybe')), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY(event_id,member_id));
CREATE TABLE IF NOT EXISTS login_codes (email TEXT PRIMARY KEY COLLATE NOCASE, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, member_id INTEGER NOT NULL REFERENCES members(id), expires_at INTEGER NOT NULL);
INSERT OR IGNORE INTO sections (id,name) VALUES (1,'Baritone & Tenor Horn');
CREATE TABLE IF NOT EXISTS attendance_verification (
  event_id INTEGER NOT NULL REFERENCES events(id),
  member_id INTEGER NOT NULL REFERENCES members(id),
  status TEXT NOT NULL CHECK(status IN ('present', 'no_show')),
  verified_by INTEGER NOT NULL REFERENCES members(id),
  verified_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (event_id, member_id)
);
