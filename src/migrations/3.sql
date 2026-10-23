CREATE TABLE access_reviews_v3 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL CHECK (length(request_id) > 0),
    visitor TEXT NOT NULL CHECK (length(visitor) > 0),
    visitor_sid BLOB NOT NULL CHECK (length(visitor_sid) BETWEEN 1 AND 64),
    method TEXT NOT NULL CHECK (length(method) > 0 AND method = upper(method)),
    api TEXT NOT NULL CHECK (substr(api, 1, 1) = '/'),
    stage INTEGER NOT NULL CHECK (stage IN (0, 1, 2, 3)),
    reason TEXT NOT NULL CHECK (length(reason) > 0),
    expired_after INTEGER NOT NULL CHECK (typeof(expired_after) = 'integer'),
    updated_at INTEGER NOT NULL CHECK (typeof(updated_at) = 'integer'),
    created_at INTEGER NOT NULL CHECK (typeof(created_at) = 'integer'),
    remember INTEGER CHECK (remember IN (0, 1)),
    decided_at INTEGER,
    grant_expires_at INTEGER,
    consumed_at INTEGER,
    invalidated_at INTEGER,
    CHECK (expired_after > created_at)
);
INSERT INTO access_reviews_v3
    (id,request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,updated_at,created_at,remember,decided_at)
SELECT id,request_id,visitor,visitor_sid,method,api,stage,reason,expired_after,updated_at,created_at,
       CASE WHEN stage != 0 THEN 1 END, CASE WHEN stage != 0 THEN updated_at END
FROM access_reviews;
INSERT INTO sqlite_sequence(name,seq)
SELECT 'access_reviews_v3',seq FROM sqlite_sequence
WHERE name='access_reviews' AND NOT EXISTS(SELECT 1 FROM sqlite_sequence WHERE name='access_reviews_v3');
UPDATE sqlite_sequence SET seq=max(seq,coalesce((SELECT seq FROM sqlite_sequence WHERE name='access_reviews'),0))
WHERE name='access_reviews_v3';
DROP TABLE access_reviews;
ALTER TABLE access_reviews_v3 RENAME TO access_reviews;
-- Preserve old IDs while merging legacy pending rows for the same scope.
UPDATE access_reviews SET stage=3
WHERE stage=0 AND id NOT IN (
    SELECT max(id) FROM access_reviews WHERE stage=0 GROUP BY visitor,visitor_sid,method,api
);
CREATE UNIQUE INDEX access_reviews_pending_scope
    ON access_reviews(visitor,visitor_sid,method,api) WHERE stage=0;
CREATE INDEX access_reviews_stage_expired_after ON access_reviews(stage,expired_after);
CREATE INDEX access_reviews_once ON access_reviews(visitor,visitor_sid,method,api,grant_expires_at)
    WHERE stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL;

-- Policy edits revoke grants for the affected methods and paths, including host SQL edits.
CREATE TRIGGER access_reviews_policy_insert AFTER INSERT ON access_rules BEGIN
    UPDATE access_reviews SET invalidated_at=CAST(strftime('%s','now') AS INTEGER)
    WHERE stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL AND ((method=NEW.method OR NEW.method='*') AND (api=NEW.api OR NEW.api='/' OR substr(api,1,length(NEW.api)+1)=NEW.api||'/'));
END;
CREATE TRIGGER access_reviews_policy_update AFTER UPDATE ON access_rules BEGIN
    UPDATE access_reviews SET invalidated_at=CAST(strftime('%s','now') AS INTEGER)
    WHERE stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL AND (((method=OLD.method OR OLD.method='*') AND (api=OLD.api OR OLD.api='/' OR substr(api,1,length(OLD.api)+1)=OLD.api||'/')) OR ((method=NEW.method OR NEW.method='*') AND (api=NEW.api OR NEW.api='/' OR substr(api,1,length(NEW.api)+1)=NEW.api||'/')));
END;
CREATE TRIGGER access_reviews_policy_delete AFTER DELETE ON access_rules BEGIN
    UPDATE access_reviews SET invalidated_at=CAST(strftime('%s','now') AS INTEGER)
    WHERE stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL AND ((method=OLD.method OR OLD.method='*') AND (api=OLD.api OR OLD.api='/' OR substr(api,1,length(OLD.api)+1)=OLD.api||'/'));
END;
CREATE TRIGGER access_reviews_contact_update AFTER UPDATE OF subject_id,status ON contacts
WHEN NEW.subject_id != OLD.subject_id OR NEW.status != OLD.status BEGIN
    UPDATE access_reviews SET invalidated_at=CAST(strftime('%s','now') AS INTEGER)
    WHERE visitor=OLD.name AND stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL;
END;
CREATE TRIGGER access_reviews_contact_delete AFTER DELETE ON contacts BEGIN
    UPDATE access_reviews SET invalidated_at=CAST(strftime('%s','now') AS INTEGER)
    WHERE visitor=OLD.name AND stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL;
END;
CREATE TRIGGER access_reviews_contact_insert AFTER INSERT ON contacts BEGIN
    UPDATE access_reviews SET invalidated_at=CAST(strftime('%s','now') AS INTEGER)
    WHERE visitor=NEW.name AND (visitor_sid != NEW.subject_id OR NEW.status=5)
      AND stage=1 AND remember=0 AND consumed_at IS NULL AND invalidated_at IS NULL;
END;
