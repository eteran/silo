package auth_test

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eteran/silo/internal/auth"

	"github.com/stretchr/testify/require"
)

const (
	AccessKeyID     = "siloadmin"
	SecretAccessKey = "siloadmin"
)

func signRequestSigV4(t *testing.T, r *http.Request) {
	t.Helper()

	const (
		region  = "us-east-1"
		service = "s3"
	)

	// Minimal SigV4 implementation for tests, matching the server's logic.
	now := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	if r.Host == "" {
		if r.URL.Host != "" {
			r.Host = r.URL.Host
		}
	}
	if r.Header.Get("Host") == "" && r.Host != "" {
		r.Header.Set("Host", r.Host)
	}

	if r.Header.Get("X-Amz-Content-Sha256") == "" {
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
	}
	r.Header.Set("X-Amz-Date", amzDate)

	signedHeaders := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	canonicalReq := auth.BuildCanonicalRequest(r, signedHeaders, r.Header.Get("X-Amz-Content-Sha256"))
	crHash := sha256.Sum256([]byte(canonicalReq))
	crHashHex := hex.EncodeToString(crHash[:])

	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		crHashHex,
	}, "\n")

	kSecret := []byte("AWS4" + SecretAccessKey)
	kDate := auth.HmacSHA256(kSecret, dateStamp)
	kRegion := auth.HmacSHA256(kDate, region)
	kService := auth.HmacSHA256(kRegion, service)
	kSigning := auth.HmacSHA256(kService, "aws4_request")
	sig := auth.HmacSHA256(kSigning, stringToSign)
	sigHex := hex.EncodeToString(sig)

	cred := strings.Join([]string{AccessKeyID, dateStamp, region, service, "aws4_request"}, "/")
	auth := strings.Join([]string{
		"AWS4-HMAC-SHA256 Credential=" + cred,
		"SignedHeaders=host;x-amz-content-sha256;x-amz-date",
		"Signature=" + sigHex,
	}, ", ")

	r.Header.Set("Authorization", auth)
}

func TestRequireAuthentication_AWSSigV4_Succeeds(t *testing.T) {
	t.Parallel()

	e := auth.NewAwsHmacAuthEngine()
	require.NotNil(t, e, "expected AWS HMAC auth engine to be created")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/test-bucket", nil)
	signRequestSigV4(t, req)

	user, err := e.AuthenticateRequest(t.Context(), req)
	require.NoError(t, err, "expected AWS SigV4 authentication to succeed")
	require.NotNil(t, user, "expected non-nil user from successful AWS SigV4 authentication")
}

func TestRequireAuthentication_AWSSigV4_InvalidSignature(t *testing.T) {

	t.Parallel()

	e := auth.NewAwsHmacAuthEngine()
	require.NotNil(t, e, "expected AWS HMAC auth engine to be created")

	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "http://example.com/test-bucket", nil)
	signRequestSigV4(t, req)

	// Corrupt the signature.
	req.Header.Set("Authorization", req.Header.Get("Authorization")+"0")

	user, err := e.AuthenticateRequest(t.Context(), req)
	require.Error(t, err, "expected AWS SigV4 authentication to fail with invalid signature")
	require.Nil(t, user, "expected nil user from failed AWS SigV4 authentication")
}
