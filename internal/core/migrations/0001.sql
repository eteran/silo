PRAGMA foreign_keys = ON;

-- Create the buckets and objects tables.
-- The buckets table stores metadata about each bucket.
-- The objects table stores metadata about each object stored in a bucket.
-- Each object is identified by its bucket and key.
-- The hash field stores the SHA-256 hash of the object's content
-- for integrity verification.
-- The size field stores the size of the object in bytes.
CREATE TABLE IF NOT EXISTS buckets (
    name TEXT PRIMARY KEY,
    created_at TIMESTAMP NOT NULL,
    modified_at TIMESTAMP NOT NULL
);

CREATE TABLE IF NOT EXISTS objects (
    bucket TEXT NOT NULL,
    key TEXT NOT NULL,
    hash TEXT NOT NULL,
    size INTEGER NOT NULL,
    content_type TEXT,
    created_at TIMESTAMP NOT NULL,
    modified_at TIMESTAMP NOT NULL,
    PRIMARY KEY (bucket, key),
    FOREIGN KEY(bucket) REFERENCES buckets(name) ON DELETE CASCADE
);

-- Create indexes used for lookups by content hash.
CREATE INDEX IF NOT EXISTS idx_objects_hash ON objects(hash);

-- Bucket tags store simple key/value metadata associated with buckets.
-- Tags are scoped to a bucket and uniquely identified by their key.
CREATE TABLE IF NOT EXISTS bucket_tags (
    bucket TEXT NOT NULL,
    key TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (bucket, key),
    FOREIGN KEY(bucket) REFERENCES buckets(name) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_bucket_tags_bucket ON bucket_tags(bucket);

-- Object tags store key/value metadata associated with individual objects.
-- Tags are scoped to a (bucket, key) pair and uniquely identified by key.
CREATE TABLE IF NOT EXISTS object_tags (
    bucket TEXT NOT NULL,
    key TEXT NOT NULL,
    tag_key TEXT NOT NULL,
    tag_value TEXT NOT NULL,
    PRIMARY KEY (bucket, key, tag_key),
    FOREIGN KEY(bucket, key) REFERENCES objects(bucket, key) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_object_tags_bucket_key ON object_tags(bucket, key);
