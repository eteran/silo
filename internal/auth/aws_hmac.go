package auth

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

const (
	AWSv4Prefix = "AWS4-HMAC-SHA256 "
)

type AwsHmacAuthEngine struct {
	AccessKeyID     string
	SecretAccessKey string
}

// NewAwsHmacAuthEngine creates a new AwsHmacAuthEngine with the given access key ID
// and secret access key.
func NewAwsHmacAuthEngine() *AwsHmacAuthEngine {
	return &AwsHmacAuthEngine{
		AccessKeyID:     "minioadmin",
		SecretAccessKey: "minioadmin",
	}
}

func awsURLEncode(s string, encodeSlash bool) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~' {
			b.WriteByte(c)
			continue
		}
		if c == '/' && !encodeSlash {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%")
		b.WriteString(strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func canonicalQueryString(u *url.URL) string {
	if u.RawQuery == "" {
		return ""
	}

	values := u.Query()
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var parts []string
	for _, k := range keys {
		vs := values[k]
		sort.Strings(vs)
		for _, v := range vs {
			encodedKey := awsURLEncode(k, true)
			encodedVal := awsURLEncode(v, true)
			parts = append(parts, encodedKey+"="+encodedVal)
		}
	}

	return strings.Join(parts, "&")
}

func canonicalHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	fields := strings.Fields(v)
	return strings.Join(fields, " ")
}

func BuildCanonicalRequest(r *http.Request, signedHeaderNames []string, payloadHash string) string {
	canonicalURI := awsURLEncode(r.URL.EscapedPath(), false)
	canonicalQS := canonicalQueryString(r.URL)

	// Headers
	lowerNames := make([]string, len(signedHeaderNames))
	for i, h := range signedHeaderNames {
		lowerNames[i] = strings.ToLower(strings.TrimSpace(h))
	}

	var hdrBuilder strings.Builder
	for _, name := range lowerNames {
		if name == "" {
			continue
		}
		var value string
		if name == "host" {
			value = r.Host
			if value == "" {
				value = r.URL.Host
			}
		} else {
			value = r.Header.Get(name)
		}
		value = canonicalHeaderValue(value)
		hdrBuilder.WriteString(name)
		hdrBuilder.WriteString(":")
		hdrBuilder.WriteString(value)
		hdrBuilder.WriteString("\n")
	}
	canonicalHeaders := hdrBuilder.String()
	canonicalSignedHeaders := strings.Join(lowerNames, ";")

	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteString("\n")
	b.WriteString(canonicalURI)
	b.WriteString("\n")
	b.WriteString(canonicalQS)
	b.WriteString("\n")
	b.WriteString(canonicalHeaders)
	b.WriteString("\n")
	b.WriteString(canonicalSignedHeaders)
	b.WriteString("\n")
	b.WriteString(payloadHash)

	return b.String()
}

func HmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// AuthenticateRequest checks the Authorization header for valid Basic Auth
// credentials. It returns a User object if the credentials are valid, nil otherwise.
func (e *AwsHmacAuthEngine) AuthenticateRequest(ctx context.Context, r *http.Request) (*User, error) {

	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, AWSv4Prefix) {
		return nil, nil
	}
	params := strings.TrimSpace(strings.TrimPrefix(auth, AWSv4Prefix))
	parts := strings.Split(params, ",")
	kv := make(map[string]string, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		idx := strings.IndexByte(p, '=')
		if idx <= 0 {
			continue
		}
		k := p[:idx]
		v := p[idx+1:]
		kv[k] = strings.TrimSpace(v)
	}

	credStr, okCred := kv["Credential"]
	signedHeadersStr, okSigned := kv["SignedHeaders"]
	signatureHex, okSig := kv["Signature"]
	if !okCred || !okSigned || !okSig {
		return nil, nil
	}

	credParts := strings.Split(credStr, "/")
	if len(credParts) != 5 {
		return nil, nil
	}
	accessKeyID := credParts[0]
	dateStamp := credParts[1]
	region := credParts[2]
	service := credParts[3]
	term := credParts[4]

	if term != "aws4_request" {
		return nil, nil
	}
	if accessKeyID != e.AccessKeyID {
		return nil, nil
	}
	if region == "" || service == "" {
		return nil, nil
	}

	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return nil, nil
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		return nil, nil
	}

	signedHeaderNames := strings.Split(signedHeadersStr, ";")
	canonicalReq := BuildCanonicalRequest(r, signedHeaderNames, payloadHash)
	crHash := sha256.Sum256([]byte(canonicalReq))
	crHashHex := hex.EncodeToString(crHash[:])

	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	var stsBuilder strings.Builder
	stsBuilder.WriteString("AWS4-HMAC-SHA256\n")
	stsBuilder.WriteString(amzDate)
	stsBuilder.WriteString("\n")
	stsBuilder.WriteString(credentialScope)
	stsBuilder.WriteString("\n")
	stsBuilder.WriteString(crHashHex)
	stringToSign := stsBuilder.String()

	kSecret := []byte("AWS4" + e.SecretAccessKey)
	kDate := HmacSHA256(kSecret, dateStamp)
	kRegion := HmacSHA256(kDate, region)
	kService := HmacSHA256(kRegion, service)
	kSigning := HmacSHA256(kService, "aws4_request")
	computedSignature := HmacSHA256(kSigning, stringToSign)

	decodedSignature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return nil, nil
	}

	if !hmac.Equal(computedSignature, decodedSignature) {
		return nil, nil
	}

	return &User{
		AccessKeyID: accessKeyID,
	}, nil

}
