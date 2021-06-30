package main

import (
	"log"
	"net/http"

	"github.com/rokmetro/auth-lib/authlib"
)

type WebAdapter struct {
	tokenAuth *authlib.TokenAuth
}

func (we WebAdapter) Start() {
	// Empty permissions indicates that no permissions are required
	http.HandleFunc("/test", we.tokenAuthWrapFunc(we.test, []string{}, "sample:read:test"))

	// Multiple permissions indicates that the requestor must have one of the provided permissions
	http.HandleFunc("/admin/test", we.tokenAuthWrapFunc(we.adminTest, []string{"admin", "lite_admin"}, ""))

	http.ListenAndServe(":5000", nil)
}

// test endpoint tests user authentication
func (we WebAdapter) test(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Access granted"))
}

// adminTest endpoint tests user authentication and admin authorization
func (we WebAdapter) adminTest(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Admin access granted"))
}

// tokenAuthWrapFunc provides a standard wrapper that performs token auth
func (we WebAdapter) tokenAuthWrapFunc(handler http.HandlerFunc, permissions []string, scope string) http.HandlerFunc {
	// Receive request with tokens generated by auth service
	return func(w http.ResponseWriter, req *http.Request) {
		// Authenticate token
		claims, err := we.tokenAuth.CheckRequestTokens(req)
		if err != nil {
			log.Printf("Authentication error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		err = we.tokenAuth.ValidatePermissionsClaim(claims, permissions)
		if err != nil {
			log.Printf("Permission error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		err = we.tokenAuth.ValidateScopeClaim(claims, scope)
		if err != nil {
			log.Printf("Scope error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		log.Printf("Authentication successful for user: %v", claims)
		handler(w, req)
	}
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(tokenAuth *authlib.TokenAuth) WebAdapter {
	return WebAdapter{tokenAuth: tokenAuth}
}

func main() {
	// Define list of services to load public keys for
	services := []string{"auth"}
	// Instantiate a remote KeyLoader to load auth public key from auth service
	serviceLoader := authlib.NewRemoteServiceRegLoader("https://auth.rokmetro.com", services)

	// Instantiate AuthService instance
	authService, err := authlib.NewAuthService("example", "https://sample.rokmetro.com", serviceLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

	// Instantiate TokenAuth instance to perform token validation
	tokenAuth := authlib.NewTokenAuth(true, authService)

	// Instantiate and start a new WebAdapter
	adapter := NewWebAdapter(tokenAuth)
	adapter.Start()
}
