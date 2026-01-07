package silo

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	AccessKeyID     = "minioadmin"
	SecretAccessKey = "minioadmin"
	BasicAuthPrefix = "Basic "
	AWSv4Prefix     = "AWS4-HMAC-SHA256 "
)

// ResponseWriterWrapper is a wrapper around the default http.ResponseWriter.
// It intercepts the WriteHeader call and saves the response status code.
type ResponseWriterWrapper struct {
	http.ResponseWriter
	WrittenResponseCode int
}

// WriteHeader intercepts the status code and stores it, then calls the original WriteHeader.
func (w *ResponseWriterWrapper) WriteHeader(statusCode int) {
	w.WrittenResponseCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// Write calls the underlying ResponseWriter's Write method.
func (w *ResponseWriterWrapper) Write(b []byte) (int, error) {
	if w.WrittenResponseCode == 0 {
		w.WrittenResponseCode = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

type LogEntry struct {
	IP         string
	Method     string
	URL        string
	Proto      string
	DurationMS float64
	StatusCode int
}

func (e LogEntry) User() slog.Attr {
	return slog.Group("user", "ip", e.IP)
}

func (e LogEntry) Request() slog.Attr {
	return slog.Group("request",
		"proto", e.Proto,
		"method", e.Method,
		"url", e.URL,
		"duration_ms", e.DurationMS,
		"status_code", e.StatusCode,
	)
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

func buildCanonicalRequest(r *http.Request, signedHeaderNames []string, payloadHash string) string {
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

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func validateAWSSignatureV4(r *http.Request, accessKey string, secretKey string) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, AWSv4Prefix) {
		return false
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
		return false
	}

	credParts := strings.Split(credStr, "/")
	if len(credParts) != 5 {
		return false
	}
	accessKeyID := credParts[0]
	dateStamp := credParts[1]
	region := credParts[2]
	service := credParts[3]
	term := credParts[4]

	if term != "aws4_request" {
		return false
	}
	if accessKeyID != accessKey {
		return false
	}
	if region == "" || service == "" {
		return false
	}

	amzDate := r.Header.Get("X-Amz-Date")
	if amzDate == "" {
		return false
	}

	payloadHash := r.Header.Get("X-Amz-Content-Sha256")
	if payloadHash == "" {
		return false
	}

	signedHeaderNames := strings.Split(signedHeadersStr, ";")
	canonicalReq := buildCanonicalRequest(r, signedHeaderNames, payloadHash)
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

	kSecret := []byte("AWS4" + secretKey)
	kDate := hmacSHA256(kSecret, dateStamp)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	computedSignature := hmacSHA256(kSigning, stringToSign)

	decodedSignature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}

	return hmac.Equal(computedSignature, decodedSignature)
}

// LogRequest is middleware that logs incoming HTTP requests.
func LogRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		entry := LogEntry{
			IP:     r.RemoteAddr,
			Method: r.Method,
			URL:    r.URL.String(),
			Proto:  r.Proto,
		}

		writer := ResponseWriterWrapper{ResponseWriter: w}

		start := time.Now()
		next.ServeHTTP(&writer, r)
		elapsed := time.Since(start).Nanoseconds()

		entry.DurationMS = float64(elapsed) / float64(time.Millisecond)
		entry.StatusCode = writer.WrittenResponseCode

		switch {
		case writer.WrittenResponseCode >= 500:
			slog.Error("Request", entry.User(), entry.Request())
		case writer.WrittenResponseCode >= 400:
			slog.Warn("Request", entry.User(), entry.Request())
		default:
			slog.Info("Request", entry.User(), entry.Request())
		}

		if false {
			var headerAttrs []any
			for key, values := range r.Header {
				for _, value := range values {
					if key == "Authorization" || key == "Cookie" {
						value = "[REDACTED]"
					}
					headerAttrs = append(headerAttrs, slog.String(key, value))
				}
			}

			slog.Debug("Request Headers", slog.Group("headers", headerAttrs...))
		}
	})
}

func validateBasicAuth(r *http.Request, accessKey string, secretKey string) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, BasicAuthPrefix) {
		return false
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(BasicAuthPrefix):]))
	if err != nil {
		return false
	}

	creds := strings.SplitN(string(payload), ":", 2)
	if len(creds) != 2 {
		return false
	}

	return creds[0] == accessKey && creds[1] == secretKey
}

// RequireAuthentication is middleware that enforces authentication for S3 API requests.
func RequireAuthentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		auth := r.Header.Get("Authorization")
		switch {
		case strings.HasPrefix(auth, AWSv4Prefix):
			if !validateAWSSignatureV4(r, AccessKeyID, SecretAccessKey) {
				writeS3Error(w, "AccessDenied", "Access Denied", r.URL.Path, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		case strings.HasPrefix(auth, BasicAuthPrefix):
			if !validateBasicAuth(r, AccessKeyID, SecretAccessKey) {
				writeS3Error(w, "AccessDenied", "Access Denied", r.URL.Path, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		default:
			writeS3Error(w, "AccessDenied", "Access Denied", r.URL.Path, http.StatusForbidden)
			return
		}
	})
}

func SlashFix(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Replace all occurrences of "//" with "/" in the URL path
		r.URL.Path = strings.ReplaceAll(r.URL.Path, "//", "/")

		if r.URL.Path != "/" && strings.HasSuffix(r.URL.Path, "/") {
			r.URL.Path = strings.TrimSuffix(r.URL.Path, "/")
		}

		next.ServeHTTP(w, r)
	})
}

func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rvr := recover(); rvr != nil {
				if rvr == http.ErrAbortHandler {
					// we don't recover http.ErrAbortHandler so the response
					// to the client is aborted, this should not be logged
					panic(rvr)
				}

				slog.Error("Internal Error in HTTP handler", "error", rvr)

				if r.Header.Get("Connection") != "Upgrade" {
					w.WriteHeader(http.StatusInternalServerError)
				}
			}
		}()

		next.ServeHTTP(w, r)
	})
}
