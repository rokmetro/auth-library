package authlib

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// TokenAuth contains configurations and helper functions required to validate tokens
type TokenAuth struct {
	authService *AuthService
}

// CheckToken the provided access token and returns the token claims
func (a *TokenAuth) CheckToken(token string, tokenType string) (map[string]interface{}, error) {
	authPubKey, err := a.authService.GetPubKey("auth")
	if authPubKey == nil || authPubKey.Key == nil {
		return nil, fmt.Errorf("failed to retrieve auth service pub key: %v", err)
	}

	parsedToken, err := new(jwt.Parser).ParseWithClaims(token, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return authPubKey.Key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse access token: %v", err)
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("failed to parse access token claims")
	}

	if claims["type"] != tokenType {
		return nil, fmt.Errorf("token type (%v) does not match %s", claims["type"], tokenType)
	}
	if claims["iss"] != authPubKey.Issuer {
		return nil, fmt.Errorf("token issuer (%v) does not match %s", claims["iss"], authPubKey.Issuer)
	}
	if claims["alg"] != authPubKey.Alg {
		return nil, fmt.Errorf("token alg (%v) does not match %s", claims["alg"], authPubKey.Alg)
	}
	if claims["kid"] != authPubKey.Kid {
		return nil, fmt.Errorf("token KID (%v) does not match %s", claims["kid"], authPubKey.Kid)
	}

	return claims, nil
}

// CheckRequestTokens is a convenience function which retrieves and checks any tokens included in a request
// and returns the access token claims
// Mobile Clients/Secure Servers: Access tokens must be provided as a Bearer token
//								  in the "Authorization" header
// Web Clients: Access tokens must be provided in the "rokwire-access-token" cookie
//				and CSRF tokens must be provided in the "CSRF" header
func (a *TokenAuth) CheckRequestTokens(r *http.Request) (map[string]interface{}, error) {
	// TODO: refactor to return standardized claims struct

	accessToken, csrfToken, err := GetRequestTokens(r)
	if err != nil {
		return nil, fmt.Errorf("error getting request tokens: %v", err)
	}

	accessClaims, err := a.CheckToken(accessToken, "access")
	if err != nil {
		return nil, fmt.Errorf("error validating access token: %v", err)
	}

	err = ValidateAccessTokenClaims(accessClaims)
	if err != nil {
		return nil, fmt.Errorf("error validating access token claims: %v", err)
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

// ValidateAccessTokenClaims will validate that the access token contains the required claims
func ValidateAccessTokenClaims(accessClaims jwt.MapClaims) error {
	// TODO: refactor to return standardized claims struct
	_, ok := accessClaims["user_id"].(string)
	if !ok {
		return fmt.Errorf("error parsing user id from access claims")
	}

	_, ok = accessClaims["client_id"].(string)
	if !ok {
		return fmt.Errorf("error parsing client id from access claims")
	}

	return nil
}

// ValidateCsrfTokenClaims will validate that the CSRF token claims appropriately match the access token claims
func ValidateCsrfTokenClaims(accessClaims jwt.MapClaims, csrfClaims jwt.MapClaims) error {
	userID, ok := accessClaims["user_id"].(string)
	if !ok {
		return fmt.Errorf("error parsing user id from access claims")
	}

	clientID, ok := accessClaims["client_id"].(string)
	if !ok {
		return fmt.Errorf("error parsing client id from access claims")
	}

	err := ValidateTokenClaim(csrfClaims, "user_id", userID)
	if err != nil {
		return err
	}

	err = ValidateTokenClaim(csrfClaims, "client_id", clientID)
	if err != nil {
		return err
	}

	return nil
}

// ValidateTokenClaim will validate that the provided token claims contain a claim matching the value provided
func ValidateTokenClaim(claims jwt.MapClaims, field string, value interface{}) error {
	claim, ok := claims[field]
	if !ok {
		return fmt.Errorf("claim not found: %s", field)
	}

	if claim != value {
		return fmt.Errorf("claim %s = %v does not match %v", field, claim, value)
	}

	return nil
}

// ValidatePermissionsClaim will validate that the provided token claims contain one or more of the required permissions
func ValidatePermissionsClaim(claims jwt.MapClaims, requiredPermissions []string) error {
	if len(requiredPermissions) == 0 {
		return nil
	}

	permissionsString, ok := claims["permissions"].(string)
	if !ok {
		return errors.New("claims do not contain permissions")
	}

	found := false
	permissions := strings.Split(permissionsString, ",")
	for _, v := range requiredPermissions {
		if containsString(permissions, v) {
			found = true
			break
		}
	}

	if !found {
		return fmt.Errorf("required permissions not found: required %v, found %s", requiredPermissions, permissionsString)
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
