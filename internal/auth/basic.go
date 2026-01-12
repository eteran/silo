package auth

import (
	"context"
	"net/http"
)

type BasicAuthEngine struct {
	AccessKeyID     string
	SecretAccessKey string
}

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
	user, pass, ok := r.BasicAuth()
	if !ok {
		return nil, nil
	}
	creds := []string{user, pass}

	if creds[0] != e.AccessKeyID || creds[1] != e.SecretAccessKey {
		return nil, nil
	}

	return &User{
		AccessKeyID: creds[0],
	}, nil
}
