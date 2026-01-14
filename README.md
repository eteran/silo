# Silo

Silo is a small, fast, and self-contained S3-compatible object storage server.
It is designed as a light-weight implementation suitable for development,
testing, and small single-node deployments.

- **Language:** Go
- **Storage:** Local filesystem (content-addressed by SHA-256) + SQLite metadata
- **API:** Subset of the S3/MinIO HTTP API
- **Auth:** Basic auth and AWS Signature V4 using static credentials

> **Status:** This is not a drop-in replacement for AWS S3. It deliberately
> implements a focused subset of the API and is intended for local use,
> testing, and experimentation.

---

## Quick Start

### Build and run

```bash
# From the repo root
GO111MODULE=on go build ./cmd/silo

# Run the server (default: HTTP on :9000, data in ./data)
./silo -listen=9000 -data-dir=./data
```

Or directly with `go run`:

```bash
go run ./cmd/silo -listen=9000 -data-dir=./data
```

### Default credentials

Silo supports both Basic Auth and AWS Signature V4. By default it uses
static credentials that match MinIO's defaults:

- Access key: `minioadmin`
- Secret key: `minioadmin`

You must supply these credentials when using S3 clients (MinIO client,
`aws s3`, SDKs, etc.).

### Using with MinIO client (mc)

You can point `mc` (MinIO client) or the MinIO Go SDK at Silo. Example
`mc` configuration:

```bash
mc alias set silo http://127.0.0.1:9000 minioadmin minioadmin
```

You can then use `mc mb`, `mc cp`, `mc ls`, etc., against the `silo` alias.

---

## Feature Matrix

The table below summarizes which S3-style features are implemented.

### Buckets

| Category      | API / Behavior                               | Status       | Notes |
| ------------- | --------------------------------------------- | ------------ | ----- |
| List buckets  | `GET /` (ListBuckets)                        | Implemented  | Returns all buckets owned by the default user. |
| Create bucket | `PUT /{bucket}`                              | Implemented  | Validates bucket name; creates metadata row. |
| Head bucket   | `HEAD /{bucket}`                             | Implemented  | 200 if exists, 404 if not. |
| Delete bucket | `DELETE /{bucket}`                           | Implemented  | Deletes bucket and associated metadata. |
| Location      | `GET /{bucket}?location`                     | Implemented  | Always returns `us-east-1` by default. |
| Bucket tagging| `PUT/GET/DELETE /{bucket}?tagging`           | Implemented  | Simple key/value tags stored in metadata. |
| Versioning    | `PUT/GET /{bucket}?versioning`               | Not implemented | |
| Encryption    | `PUT/GET/DELETE /{bucket}?encryption`        | Not implemented | |
| CORS          | `PUT/GET/DELETE /{bucket}?cors`              | Not implemented | |
| Lifecycle     | `PUT/GET/DELETE /{bucket}?lifecycle`         | Not implemented | |
| Notifications | `PUT/GET /{bucket}?notification`             | Not implemented | |
| Policy        | `PUT/GET/DELETE /{bucket}?policy`            | Not implemented | |
| Replication   | `PUT/GET/DELETE /{bucket}?replication`       | Not implemented | |
| Multi-delete  | `POST /{bucket}?delete`                      | Not implemented | |
| Multipart list| `GET /{bucket}?uploads`                      | Not implemented | |

### Objects

| Category           | API / Behavior                                    | Status       | Notes |
| ------------------ | -------------------------------------------------- | ------------ | ----- |
| Put object         | `PUT /{bucket}/{key}`                             | Implemented  | Stores payload as SHA-256 blob on disk, metadata in SQLite. |
| Get object         | `GET /{bucket}/{key}`                             | Implemented  | Streams from local storage. |
| Head object        | `HEAD /{bucket}/{key}`                            | Implemented  | Returns metadata and content length/type. |
| Delete object      | `DELETE /{bucket}/{key}`                          | Implemented  | Removes metadata and underlying blob (if unreferenced). |
| Object tagging     | `PUT/GET/DELETE /{bucket}/{key}?tagging`          | Implemented  | Object-level tags. |
| Copy object        | `PUT /{bucket}/{key}` with `x-amz-copy-source`    | Implemented  | Copies metadata; payload must exist. No multipart copy. |
| Get attributes     | `GET /{bucket}/{key}?attributes`                  | Not implemented | |
| Restore object     | `POST /{bucket}/{key}?restore`                    | Not implemented | |
| SelectObjectContent| `POST /{bucket}/{key}?select`                     | Not implemented | |

### Listing

| Category        | API / Behavior                           | Status       | Notes |
| --------------- | ----------------------------------------- | ------------ | ----- |
| ListObjects v1  | `GET /{bucket}`                          | Implemented  | Supports `prefix`, `delimiter`. |
| ListObjects v2  | `GET /{bucket}?list-type=2`              | Implemented  | Supports `prefix`, `start-after`, pagination. |
| List versions   | `GET /{bucket}?versions`                 | Not implemented | |

### Multipart Uploads

| Category           | API / Behavior                                             | Status       | Notes |
| ------------------ | --------------------------------------------------------- | ------------ | ----- |
| CreateMultipartUpload | `POST /{bucket}/{key}?uploads`                        | Implemented  | Creates upload ID and directory under `data/uploads/{uploadId}`. |
| UploadPart         | `PUT /{bucket}/{key}?uploadId=ID&partNumber=N`            | Implemented  | Writes `part-%06d` files; supports regular and streaming V4 payloads. |
| CompleteMultipartUpload | `POST /{bucket}/{key}?uploadId=ID`                  | Implemented  | Concatenates parts, stores into primary storage, updates metadata. |
| AbortMultipartUpload | `DELETE /{bucket}/{key}?uploadId=ID`                   | Implemented  | Deletes temporary upload directory. |
| ListParts          | `GET /{bucket}/{key}?uploadId=ID`                         | Implemented  | Returns part list with size, ETag, pagination. |
| UploadPartCopy     | `PUT ...?uploadId=ID&partNumber=N` + `x-amz-copy-source`  | Not implemented | |
| ListMultipartUploads | `GET /{bucket}?uploads`                                | Not implemented | |

### Authentication & Security

| Category       | Behavior                                     | Status      | Notes |
| -------------- | -------------------------------------------- | ----------- | ----- |
| Basic Auth     | `Authorization: Basic ...`                   | Implemented | Uses static `minioadmin:minioadmin` by default. |
| AWS SigV4      | `Authorization: AWS4-HMAC-SHA256 ...`        | Implemented | Compatible with MinIO/AWS SDKs for tested operations. |
| TLS            | HTTPS listener                               | Partially implemented | Server supports TLS config, but CLI currently hard-codes paths; see `cmd/silo`. |

---

## Storage Model

Silo stores data in a single directory tree (configurable via `-data-dir`):

- `data/metadata.sqlite` – SQLite database holding buckets, objects, tags.
- `data/objects/<hh>/<hash>` – content-addressed objects, where `<hash>` is
  the SHA-256 of the payload and `<hh>` is its first two hex characters.
- `data/uploads/<uploadId>/part-000001` – temporary multipart upload parts.

Multiple objects (or versions of metadata) can reference the same underlying
blob when the payload is identical.

---

## Design Goals

- **Lightweight:** single binary with minimal moving parts (SQLite + files).
- **Fast local testing:** easy to run alongside applications or in CI.
- **S3/MinIO friendly:** compatible with common S3 operations, MinIO client,
  and the MinIO Go SDK for the supported subset.
- **Simple codebase:** focus on readability and explicit behavior over
  configuration complexity.

---

## Non-Goals / Limitations

- No support for cross-region replication, advanced IAM policies, or
  complex security models.
- No bucket versioning or object locking semantics.
- No advanced analytics features like SelectObjectContent.
- Single-node, local-filesystem only; no clustering or distributed storage.

---

## Development

Run the test suite:

```bash
go test ./...
```

During development, you can use the provided example and UI binaries under
`cmd/example` and `cmd/silo-ui` as references for embedding or extending
Silo.
