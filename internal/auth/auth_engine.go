package auth

import (
	"context"
	"net/http"
)

const (
	DefaultAccessKeyID     = "siloadmin"
	DefaultSecretAccessKey = "siloadmin"
)

type User struct {
	AccessKeyID string
}

type AuthEngine interface {

	// AuthenticateRequest inspects the given HTTP request for valid
	// authentication credentials. If valid, it returns a User object; otherwise, it
	// returns nil. An error is returned if there was an issue processing
	// the authentication.
	AuthenticateRequest(ctx context.Context, rq *http.Request) (*User, error)
}
