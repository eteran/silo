package auth

import (
	"context"
	"net/http"
)

type CompoundAuthEngine struct {
	engines []AuthEngine
}

// NewCompoundAuthEngine creates a new CompoundAuthEngine with the given AuthEngines.
func NewCompoundAuthEngine(engines ...AuthEngine) *CompoundAuthEngine {
	return &CompoundAuthEngine{
		engines: engines,
	}
}

// AuthenticateRequest checks the Authorization header for valid Basic Auth
// credentials. It returns a User object if the credentials are valid, nil otherwise.
func (e *CompoundAuthEngine) AuthenticateRequest(ctx context.Context, r *http.Request) (*User, error) {

	for _, engine := range e.engines {
		if user, err := engine.AuthenticateRequest(ctx, r); user != nil && err == nil {
			return user, nil
		}
	}

	return nil, nil
}
