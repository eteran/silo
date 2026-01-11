package auth

import "net/http"

type AuthEngine interface {

	// AuthenticateRequest inspects the given HTTP request for valid
	// authentication credentials. If valid, it returns true; otherwise, it
	// returns false. An error is returned if there was an issue processing
	// the authentication.
	AuthenticateRequest(rq *http.Request) (bool, error)
}
