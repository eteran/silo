package auth

import (
	"context"
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
		AccessKeyID:     DefaultAccessKeyID,
		SecretAccessKey: DefaultSecretAccessKey,
	}
}

// AuthenticateRequest checks the Authorization header for valid Basic Auth
// credentials. It returns a User object if the credentials are valid, nil otherwise.
func (e *BasicAuthEngine) AuthenticateRequest(ctx context.Context, r *http.Request) (*User, error) {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, BasicAuthPrefix) {
		return nil, nil
	}

	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(BasicAuthPrefix):]))
	if err != nil {
		return nil, nil
	}

	creds := strings.SplitN(string(payload), ":", 2)
	if len(creds) != 2 {
		return nil, nil
	}

	if creds[0] != e.AccessKeyID || creds[1] != e.SecretAccessKey {
		return nil, nil
	}

	return &User{
		AccessKeyID: creds[0],
	}, nil
}
