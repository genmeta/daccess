-- Rebuild the contact table to permit updates after expiry and shared aliases.
CREATE TABLE contacts_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE CHECK (length(name) > 0),
    subject_id BLOB NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    alias TEXT,
    class TEXT NOT NULL DEFAULT '',
    grants TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(grants) AND json_type(grants) = 'object'),
    offers TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(offers) AND json_type(offers) = 'object'),
    requests TEXT NOT NULL DEFAULT '{}' CHECK (json_valid(requests) AND json_type(requests) = 'object'),
    description TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 80),
    status INTEGER NOT NULL CHECK (status IN (0, 2, 3, 4, 5)),
    expired_after INTEGER NOT NULL CHECK (typeof(expired_after) = 'integer'),
    updated_at INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer'),
    created_at INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
    CHECK (created_at <= updated_at)
);
INSERT INTO contacts_v2 SELECT * FROM contacts;
-- Keep the AUTOINCREMENT high water mark, including deleted rows.
INSERT INTO sqlite_sequence(name, seq)
SELECT 'contacts_v2', seq FROM sqlite_sequence
WHERE name = 'contacts' AND NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name = 'contacts_v2');
UPDATE sqlite_sequence SET seq = max(seq, coalesce((SELECT seq FROM sqlite_sequence WHERE name = 'contacts'), 0))
WHERE name = 'contacts_v2';
DROP TRIGGER contacts_delete_exact_rules;
DROP TABLE contacts;
ALTER TABLE contacts_v2 RENAME TO contacts;
CREATE INDEX contacts_status_expired_after ON contacts (status, expired_after);
CREATE INDEX contacts_updated_at ON contacts (updated_at, name);

CREATE TABLE contact_deletions (
    name TEXT PRIMARY KEY,
    updated_at INTEGER NOT NULL
);
CREATE TRIGGER contacts_updated AFTER UPDATE ON contacts
WHEN NEW.updated_at = OLD.updated_at
BEGIN
    UPDATE contacts SET updated_at = max(OLD.updated_at, CAST(strftime('%s', 'now') AS INTEGER)) WHERE id = NEW.id;
END;
CREATE TRIGGER contacts_inserted AFTER INSERT ON contacts
BEGIN
    DELETE FROM contact_deletions WHERE name = NEW.name;
END;
CREATE TRIGGER contacts_delete_exact_rules AFTER DELETE ON contacts
BEGIN
    DELETE FROM access_rules WHERE grantee = OLD.name;
    INSERT INTO contact_deletions(name, updated_at) VALUES(OLD.name, CAST(strftime('%s', 'now') AS INTEGER))
    ON CONFLICT(name) DO UPDATE SET updated_at = excluded.updated_at;
END;
