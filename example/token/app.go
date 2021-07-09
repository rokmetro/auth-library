package main

import (
	"log"
	"net/http"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/tokenauth"
)

type WebAdapter struct {
	tokenAuth *tokenauth.TokenAuth
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

// adminTokenWrapFunc
func (we WebAdapter) adminTokenWrapFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		// Authenticate token
		claims, err := we.tokenAuth.CheckRequestTokens(req)
		if err != nil {
			log.Printf("Authentication error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		err = we.tokenAuth.AuthorizeRequestPermissions(claims, req)
		if err != nil {
			log.Printf("Permission error: %v\n", err)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}

		log.Printf("Authentication successful for user: %v", claims)
		handler(w, req)
	}
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(tokenAuth *tokenauth.TokenAuth) WebAdapter {
	return WebAdapter{tokenAuth: tokenAuth}
}

func main() {
	// Instantiate a remote ServiceRegLoader to load auth service registration record from auth service
	serviceLoader := authservice.NewRemoteServiceRegLoader("https://auth.rokmetro.com", nil)

	// Instantiate AuthService instance
	authService, err := authservice.NewAuthService("example", "https://sample.rokmetro.com", serviceLoader)
	if err != nil {
		log.Fatalf("Error initializing auth service: %v", err)
	}

	permissionAuth := authorization.NewCasbinAuthorization("./permissions_authorization_policy.csv")
	scopeAuth := authorization.NewCasbinAuthorization("./scope_authorization_policy.csv")
	// Instantiate TokenAuth instance to perform token validation
	tokenAuth, err := tokenauth.NewTokenAuth(true, authService, permissionAuth, scopeAuth)
	if err != nil {
		log.Fatalf("Error intitializing token auth: %v", err)
	}

	// Instantiate and start a new WebAdapter
	adapter := NewWebAdapter(tokenAuth)
	adapter.Start()
}
