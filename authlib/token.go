package authlib

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

type Claims struct {
	// Required Standard Claims: sub, exp, iat
	jwt.StandardClaims
	ClientID    string `json:"client_id" validate:"required"`
	Purpose     string `json:"purpose" validate:"required"`
	Permissions string `json:"permissions"`
	Groups      string `json:"groups"`
}

// TokenAuth contains configurations and helper functions required to validate tokens
type TokenAuth struct {
	authService *AuthService
}

// CheckToken validates the provided token and returns the token claims
func (a *TokenAuth) CheckToken(token string, purpose string) (*Claims, error) {
	authPubKey, err := a.authService.GetPubKey("auth")
	if authPubKey == nil || authPubKey.Key == nil {
		return nil, fmt.Errorf("failed to retrieve auth service pub key: %v", err)
	}

	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return authPubKey.Key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	if !parsedToken.Valid {
		return nil, errors.New("token invalid")
	}

	claims, ok := parsedToken.Claims.(*Claims)
	if !ok {
		return nil, errors.New("failed to parse token claims")
	}

	// Check token claims
	if claims.Subject == "" {
		return nil, errors.New("token sub missing")
	}
	if claims.ExpiresAt == 0 {
		return nil, errors.New("token exp missing")
	}
	if claims.IssuedAt == 0 {
		return nil, errors.New("token iat missing")
	}
	if claims.ClientID == "" {
		return nil, errors.New("token client_id missing")
	}
	if claims.Issuer != authPubKey.Issuer {
		return nil, fmt.Errorf("token issuer (%v) does not match %s", claims.Issuer, authPubKey.Issuer)
	}
	if claims.Purpose != purpose {
		return nil, fmt.Errorf("token purpose (%v) does not match %s", claims.Purpose, purpose)
	}

	// Check token headers
	alg, _ := parsedToken.Header["alg"].(string)
	if alg != authPubKey.Alg {
		return nil, fmt.Errorf("token alg (%v) does not match %s", alg, authPubKey.Alg)
	}
	typ, _ := parsedToken.Header["typ"].(string)
	if alg != authPubKey.Alg {
		return nil, fmt.Errorf("token typ (%v) does not match JWT", typ)
	}

	return claims, nil
}

// CheckRequestTokens is a convenience function which retrieves and checks any tokens included in a request
// and returns the access token claims
// Mobile Clients/Secure Servers: Access tokens must be provided as a Bearer token
//								  in the "Authorization" header
// Web Clients: Access tokens must be provided in the "rokwire-access-token" cookie
//				and CSRF tokens must be provided in the "CSRF" header
func (a *TokenAuth) CheckRequestTokens(r *http.Request) (*Claims, error) {
	accessToken, csrfToken, err := GetRequestTokens(r)
	if err != nil {
		return nil, fmt.Errorf("error getting request tokens: %v", err)
	}

	accessClaims, err := a.CheckToken(accessToken, "access")
	if err != nil {
		return nil, fmt.Errorf("error validating access token: %v", err)
	}

	if csrfToken != "" {
		csrfClaims, err := a.CheckToken(csrfToken, "csrf")
		if err != nil {
			return nil, fmt.Errorf("error validating csrf token: %v", err)
		}

		err = ValidateCsrfTokenClaims(accessClaims, csrfClaims)
		if err != nil {
			return nil, fmt.Errorf("error validating csrf token claims: %v", err)
		}
	}

	return accessClaims, nil
}

// NewTokenAuth creates and configures a new TokenAuth instance
func NewTokenAuth(authService *AuthService) *TokenAuth {
	return &TokenAuth{authService: authService}
}

// -------------------------- Helper Functions --------------------------

// ValidateCsrfTokenClaims will validate that the CSRF token claims appropriately match the access token claims
func ValidateCsrfTokenClaims(accessClaims *Claims, csrfClaims *Claims) error {
	if csrfClaims.Subject != accessClaims.Subject {
		return fmt.Errorf("csrf sub (%s) does not match access sub (%s)", csrfClaims.Subject, accessClaims.Subject)
	}

	if csrfClaims.ClientID != accessClaims.ClientID {
		return fmt.Errorf("csrf client_id (%s) does not match access client_id (%s)", csrfClaims.ClientID, accessClaims.ClientID)
	}

	return nil
}

// ValidatePermissionsClaim will validate that the provided token claims contain one or more of the required permissions
func ValidatePermissionsClaim(claims *Claims, requiredPermissions []string) error {
	if len(requiredPermissions) == 0 {
		return nil
	}

	if claims.Permissions == "" {
		return errors.New("permissions claim empty")
	}

	found := false
	permissions := strings.Split(claims.Permissions, ",")
	for _, v := range requiredPermissions {
		if containsString(permissions, v) {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("required permissions not found: required %v, found %s", requiredPermissions, claims.Permissions)
	}

	return nil
}

// GetRequestTokens retrieves tokens from the request headers and/or cookies
// Mobile Clients/Secure Servers: Access tokens must be provided as a Bearer token
//								  in the "Authorization" header
// Web Clients: Access tokens must be provided in the "rokwire-access-token" cookie
//				and CSRF tokens must be provided in the "CSRF" header
func GetRequestTokens(r *http.Request) (string, string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader == "" {
		splitAuthorization := strings.Fields(authorizationHeader)
		if len(splitAuthorization) != 2 {
			return "", "", errors.New("invalid authorization header format")
		}
		if strings.ToLower(splitAuthorization[0]) != "bearer" {
			return "", "", errors.New("authorization header missing bearer token")
		}
		idToken := splitAuthorization[1]

		return idToken, "", nil
	}

	csrfToken := r.Header.Get("CSRF")
	if csrfToken == "" {
		return "", "", errors.New("missing authorization and csrf header")
	}

	accessCookie, err := r.Cookie("rokwire-access-token")
	if err != nil || accessCookie == nil || accessCookie.Value == "" {
		return "", "", errors.New("missing access token")
	}

	return accessCookie.Value, csrfToken, nil
}
