package tokenauth

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authutils"
)

// Claims represents the standard claims included in access tokens
type Claims struct {
	// Required Standard Claims: sub, aud, exp, iat
	jwt.StandardClaims
	OrgID       string `json:"org_id" validate:"required"`
	Purpose     string `json:"purpose" validate:"required"`
	Permissions string `json:"permissions"`
	Scope       string `json:"scope"`
}

// TokenAuth contains configurations and helper functions required to validate tokens
type TokenAuth struct {
	authService         *authservice.AuthService
	acceptRokwireTokens bool
}

// CheckToken validates the provided token and returns the token claims
func (t *TokenAuth) CheckToken(token string, purpose string) (*Claims, error) {
	authServiceReg, err := t.authService.GetServiceReg("auth")
	if err != nil || authServiceReg == nil || authServiceReg.PubKey == nil || authServiceReg.PubKey.Key == nil {
		return nil, fmt.Errorf("failed to retrieve auth service pub key: %v", err)
	}

	parsedToken, err := jwt.ParseWithClaims(token, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return authServiceReg.PubKey.Key, nil
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
	if claims.OrgID == "" {
		return nil, errors.New("token org_id missing")
	}
	if claims.Issuer != authServiceReg.Host {
		return nil, fmt.Errorf("token iss (%s) does not match %s", claims.Issuer, authServiceReg.Host)
	}
	if claims.Purpose != purpose {
		return nil, fmt.Errorf("token purpose (%s) does not match %s", claims.Purpose, purpose)
	}

	aud := strings.Split(claims.Audience, ",")
	if !(authutils.ContainsString(aud, t.authService.GetServiceID()) || (t.acceptRokwireTokens && authutils.ContainsString(aud, "rokwire"))) {
		acceptAuds := t.authService.GetServiceID()
		if t.acceptRokwireTokens {
			acceptAuds += " or rokwire"
		}

		return nil, fmt.Errorf("token aud (%s) does not match %s", claims.Audience, acceptAuds)
	}

	// Check token headers
	alg, _ := parsedToken.Header["alg"].(string)
	if alg != authServiceReg.PubKey.Alg {
		return nil, fmt.Errorf("token alg (%v) does not match %s", alg, authServiceReg.PubKey.Alg)
	}
	typ, _ := parsedToken.Header["typ"].(string)
	if typ != "JWT" {
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
func (t *TokenAuth) CheckRequestTokens(r *http.Request) (*Claims, error) {
	accessToken, csrfToken, err := GetRequestTokens(r)
	if err != nil {
		return nil, fmt.Errorf("error getting request tokens: %v", err)
	}

	accessClaims, err := t.CheckToken(accessToken, "access")
	if err != nil {
		return nil, fmt.Errorf("error validating access token: %v", err)
	}

	if csrfToken != "" {
		csrfClaims, err := t.CheckToken(csrfToken, "csrf")
		if err != nil {
			return nil, fmt.Errorf("error validating csrf token: %v", err)
		}

		err = t.ValidateCsrfTokenClaims(accessClaims, csrfClaims)
		if err != nil {
			return nil, fmt.Errorf("error validating csrf token claims: %v", err)
		}
	}

	return accessClaims, nil
}

// ValidateCsrfTokenClaims will validate that the CSRF token claims appropriately match the access token claims
//	Returns nil on success and error on failure.
func (t *TokenAuth) ValidateCsrfTokenClaims(accessClaims *Claims, csrfClaims *Claims) error {
	if csrfClaims.Subject != accessClaims.Subject {
		return fmt.Errorf("csrf sub (%s) does not match access sub (%s)", csrfClaims.Subject, accessClaims.Subject)
	}

	if csrfClaims.OrgID != accessClaims.OrgID {
		return fmt.Errorf("csrf org_id (%s) does not match access org_id (%s)", csrfClaims.OrgID, accessClaims.OrgID)
	}

	return nil
}

// ValidatePermissionsClaim will validate that the provided token claims contain one or more of the required permissions
//	Returns nil on success and error on failure.
func (t *TokenAuth) ValidatePermissionsClaim(claims *Claims, requiredPermissions []string) error {
	if len(requiredPermissions) == 0 {
		return nil
	}

	if claims.Permissions == "" {
		return errors.New("permissions claim empty")
	}

	// Grant access if claims contain any of the required permissions
	permissions := strings.Split(claims.Permissions, ",")
	for _, v := range requiredPermissions {
		if authutils.ContainsString(permissions, v) {
			return nil
		}
	}

	return fmt.Errorf("required permissions not found: required %v, found %s", requiredPermissions, claims.Permissions)
}

// ValidateScopeClaim will validate that the provided token claims contain the required scope
// 	If an empty required scope is provided, the claims must contain a valid global scope such as 'all' or '{service}:all'
//	Returns nil on success and error on failure.
func (t *TokenAuth) ValidateScopeClaim(claims *Claims, requiredScope string) error {
	if claims.Scope == "" {
		return errors.New("scope claim empty")
	}

	// Grant access for global scope
	if claims.Scope == "all" {
		return nil
	}

	scopes := strings.Split(claims.Scope, " ")

	// Grant access if claims contain service-level global scope
	serviceAll := t.authService.GetServiceID() + ":all"
	if authutils.ContainsString(scopes, serviceAll) {
		return nil
	}

	// Deny access if no required scope is provided
	if requiredScope == "" {
		return fmt.Errorf("no required scope")
	}

	// Grant access if claims contain required scope
	if authutils.ContainsString(scopes, requiredScope) {
		return nil
	}

	return fmt.Errorf("required scope not found: required %s, found %s", requiredScope, claims.Scope)
}

// NewTokenAuth creates and configures a new TokenAuth instance
func NewTokenAuth(acceptRokwireTokens bool, authService *authservice.AuthService) (*TokenAuth, error) {
	authService.SubscribeServices([]string{"auth"}, true)
	return &TokenAuth{acceptRokwireTokens: acceptRokwireTokens, authService: authService}, nil
}

// -------------------------- Helper Functions --------------------------

// GetRequestTokens retrieves tokens from the request headers and/or cookies
// Mobile Clients/Secure Servers: Access tokens must be provided as a Bearer token
//								  in the "Authorization" header
// Web Clients: Access tokens must be provided in the "rokwire-access-token" cookie
//				and CSRF tokens must be provided in the "CSRF" header
func GetRequestTokens(r *http.Request) (string, string, error) {
	authorizationHeader := r.Header.Get("Authorization")
	if authorizationHeader != "" {
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
