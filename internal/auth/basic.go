package auth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

type BasicAuthEngine struct {
	AccessKeyID     string
	SecretAccessKey string
}

const (
	BasicAuthPrefix = "Basic "
)

// NewBasicAuthEngine creates a new BasicAuthEngine with the given access key ID
// and secret access key.
func NewBasicAuthEngine() *BasicAuthEngine {
	return &BasicAuthEngine{
		AccessKeyID:     "minioadmin",
		SecretAccessKey: "minioadmin",
	}
}

// AuthenticateRequest checks the Authorization header for valid Basic Auth
// credentials. It returns true if the credentials are valid, false otherwise.
func (e *BasicAuthEngine) AuthenticateRequest(r *http.Request) (bool, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, BasicAuthPrefix) {
		return false, nil
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(BasicAuthPrefix):]))
	if err != nil {
		return false, nil
	}

	creds := strings.SplitN(string(payload), ":", 2)
	if len(creds) != 2 {
		return false, nil
	}

	return creds[0] == e.AccessKeyID && creds[1] == e.SecretAccessKey, nil
}
