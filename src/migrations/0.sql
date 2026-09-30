CREATE TABLE module (
    module_name  TEXT PRIMARY KEY CHECK (length(module_name) > 0),
    version      INTEGER NOT NULL CHECK (version >= 0),
    descriptions TEXT NOT NULL DEFAULT '',
    keywords     TEXT NOT NULL DEFAULT '[]'
        CHECK (json_valid(keywords) AND json_type(keywords) = 'array'),
    author       TEXT,
    license      TEXT,
    dependencies TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(dependencies) AND json_type(dependencies) = 'object')
);

CREATE TRIGGER module_single_row
BEFORE INSERT ON module
WHEN EXISTS (SELECT 1 FROM module)
BEGIN
    SELECT RAISE(ABORT, 'module table can contain only one row');
END;

INSERT INTO module (
    module_name,
    version,
    descriptions,
    keywords,
    author,
    license,
    dependencies
) VALUES (
    'access',
    0,
    'Name-based access control for DHTTP',
    '["access-control","dhttp"]',
    NULL,
    'Apache-2.0',
    '{}'
);

CREATE TABLE contacts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    name         TEXT NOT NULL UNIQUE CHECK (length(name) > 0),
    subject_id   BLOB NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 64),
    alias        TEXT UNIQUE,
    class        TEXT NOT NULL DEFAULT '',
    grants       TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(grants) AND json_type(grants) = 'object'),
    offers       TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(offers) AND json_type(offers) = 'object'),
    requests     TEXT NOT NULL DEFAULT '{}'
        CHECK (json_valid(requests) AND json_type(requests) = 'object'),
    description  TEXT NOT NULL DEFAULT '' CHECK (length(description) <= 80),
    status       INTEGER NOT NULL CHECK (status IN (0, 2, 3, 4, 5)),
    expired_after INTEGER NOT NULL CHECK (typeof(expired_after) = 'integer'),
    updated_at    INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer'),
    created_at    INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
    CHECK (created_at <= updated_at AND updated_at < expired_after)
);

CREATE INDEX contacts_status_expired_after ON contacts (status, expired_after);

CREATE TABLE access_rules (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    method       TEXT NOT NULL CHECK (length(method) > 0 AND method = upper(method)),
    api          TEXT NOT NULL CHECK (
        substr(api, 1, 1) = '/' AND (api = '/' OR substr(api, -1, 1) != '/')
    ),
    effect       TEXT NOT NULL CHECK (effect IN ('allow', 'review', 'deny')),
    grantee_type INTEGER NOT NULL CHECK (grantee_type IN (0, 1, 2, 3, 4)),
    grantee      TEXT NOT NULL CHECK (length(grantee) > 0),
    updated_at    INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer'),
    created_at    INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
    UNIQUE (grantee, method, api)
);

CREATE INDEX access_rules_api_method ON access_rules (api, method);
CREATE INDEX access_rules_grantee ON access_rules (grantee);

CREATE TABLE access_reviews (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id    TEXT NOT NULL CHECK (length(request_id) > 0),
    visitor      TEXT NOT NULL CHECK (length(visitor) > 0),
    visitor_sid  BLOB NOT NULL CHECK (length(visitor_sid) BETWEEN 1 AND 64),
    method       TEXT NOT NULL CHECK (length(method) > 0 AND method = upper(method)),
    api          TEXT NOT NULL CHECK (substr(api, 1, 1) = '/'),
    stage        INTEGER NOT NULL CHECK (stage IN (0, 1, 2)),
    reason       TEXT NOT NULL CHECK (length(reason) > 0),
    expired_after INTEGER NOT NULL CHECK (typeof(expired_after) = 'integer'),
    updated_at     INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer'),
    created_at     INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
    UNIQUE (visitor, request_id),
    CHECK (expired_after > created_at)
);

CREATE INDEX access_reviews_visitor_request
    ON access_reviews (visitor, request_id);
CREATE INDEX access_reviews_stage_expired_after
    ON access_reviews (stage, expired_after);

CREATE TRIGGER access_rules_anyone_exclusive_insert
BEFORE INSERT ON access_rules
WHEN (NEW.grantee = '*?' AND EXISTS (
        SELECT 1 FROM access_rules
        WHERE method = NEW.method AND api = NEW.api AND grantee IN ('**', '?')
    ))
 OR (NEW.grantee IN ('**', '?') AND EXISTS (
        SELECT 1 FROM access_rules
        WHERE method = NEW.method AND api = NEW.api AND grantee = '*?'
    ))
BEGIN
    SELECT RAISE(ABORT, 'anyone selector conflicts with named or anonymous selector');
END;

CREATE TRIGGER access_rules_anyone_exclusive_update
BEFORE UPDATE OF grantee, method, api ON access_rules
WHEN (NEW.grantee = '*?' AND EXISTS (
        SELECT 1 FROM access_rules
        WHERE id != NEW.id AND method = NEW.method AND api = NEW.api
          AND grantee IN ('**', '?')
    ))
 OR (NEW.grantee IN ('**', '?') AND EXISTS (
        SELECT 1 FROM access_rules
        WHERE id != NEW.id AND method = NEW.method AND api = NEW.api
          AND grantee = '*?'
    ))
BEGIN
    SELECT RAISE(ABORT, 'anyone selector conflicts with named or anonymous selector');
END;

CREATE TRIGGER contacts_delete_exact_rules
AFTER DELETE ON contacts
BEGIN
    DELETE FROM access_rules WHERE grantee = OLD.name;
END;
