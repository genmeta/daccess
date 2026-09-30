CREATE TABLE contact_applications (
    application_id TEXT PRIMARY KEY CHECK (length(application_id) = 64),
    applicant_name TEXT NOT NULL CHECK (length(applicant_name) > 0),
    applicant_sid BLOB NOT NULL CHECK (length(applicant_sid) BETWEEN 1 AND 64),
    payload_hash TEXT NOT NULL CHECK (length(payload_hash) = 64),
    status TEXT NOT NULL CHECK (status IN ('pending', 'active', 'expired', 'denied', 'revoked')),
    received_at INTEGER NOT NULL CHECK (typeof(received_at) = 'integer'),
    expired_after INTEGER NOT NULL CHECK (typeof(expired_after) = 'integer'),
    CHECK (expired_after > received_at)
);

CREATE INDEX contact_applications_applicant
    ON contact_applications (applicant_name, status, received_at);
