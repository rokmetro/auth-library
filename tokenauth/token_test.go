package tokenauth_test

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authservice/mocks"
	"github.com/rokmetro/auth-library/authutils"
	"github.com/rokmetro/auth-library/internal/testutils"
	"github.com/rokmetro/auth-library/tokenauth"
)

func setupTestTokenAuth(acceptRokwire bool, mockLoader *mocks.ServiceRegLoader) (*tokenauth.TokenAuth, error) {
	auth, err := testutils.SetupTestAuthService(mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	return tokenauth.NewTokenAuth(acceptRokwire, auth)
}

func generateTestToken(claims *tokenauth.Claims, key *rsa.PrivateKey) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	kid, err := authutils.GetKeyFingerprint(&key.PublicKey)
	if err != nil {
		return "", fmt.Errorf("error computing auth key fingerprint: %v", err)
	}
	token.Header["kid"] = kid
	return token.SignedString(key)
}

func getTestClaims(sub string, aud string, orgID string, purpose string, issuer string, permissions string, scope string, exp int64) *tokenauth.Claims {
	return &tokenauth.Claims{
		StandardClaims: jwt.StandardClaims{
			Audience:  aud,
			Subject:   sub,
			ExpiresAt: exp,
			IssuedAt:  time.Now().Unix(),
			Issuer:    issuer,
		}, OrgID: orgID, Purpose: purpose, Permissions: permissions, Scope: scope,
	}
}

func getSampleValidClaims() *tokenauth.Claims {
	exp := time.Now().Add(30 * time.Minute)
	return getTestClaims("test_user_id", "rokwire", "test_org_id", "access",
		"https://auth.rokmetro.com", "example_permission", "all", exp.Unix())
}

func getSampleExpiredClaims() *tokenauth.Claims {
	exp := time.Now().Add(-5 * time.Minute)
	return getTestClaims("test_user_id", "rokwire", "test_org_id", "access",
		"https://auth.rokmetro.com", "example_permission", "all", exp.Unix())
}

func TestTokenAuth_CheckToken(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokmetro.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokmetro.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	// Valid rokwire
	validClaims := getSampleValidClaims()
	validToken, err := generateTestToken(validClaims, testutils.GetSamplePrivKey())
	if err != nil {
		t.Errorf("Error initializing valid token: %v", err)
	}

	// Valid audience
	validAudClaims := getSampleValidClaims()
	validAudClaims.Audience = "test"
	validAudToken, err := generateTestToken(validAudClaims, testutils.GetSamplePrivKey())
	if err != nil {
		t.Errorf("Error initializing valid aud token: %v", err)
	}

	// Expired
	expiredToken, err := generateTestToken(getSampleExpiredClaims(), testutils.GetSamplePrivKey())
	if err != nil {
		t.Errorf("Error initializing expired token: %v", err)
	}

	// Invalid issuer
	invalidIssClaims := getSampleValidClaims()
	invalidIssClaims.Issuer = "https://auth2.rokmetro.com"
	invalidIssToken, err := generateTestToken(invalidIssClaims, testutils.GetSamplePrivKey())
	if err != nil {
		t.Errorf("Error initializing invalid iss token: %v", err)
	}

	// Invalid audience
	invalidAudClaims := getSampleValidClaims()
	invalidAudClaims.Audience = "test2"
	invalidAudToken, err := generateTestToken(invalidAudClaims, testutils.GetSamplePrivKey())
	if err != nil {
		t.Errorf("Error initializing invalid aud token: %v", err)
	}

	type args struct {
		token   string
		purpose string
	}
	tests := []struct {
		name          string
		args          args
		acceptRokwire bool
		want          *tokenauth.Claims
		wantErr       bool
		errSubstring  string
	}{
		{"return claims on valid rokwire token", args{validToken, "access"}, true, validClaims, false, ""},
		{"return claims on valid aud token", args{validAudToken, "access"}, false, validAudClaims, false, ""},
		{"return error on invalid token", args{"token", "access"}, true, nil, true, "failed to parse token"},
		{"return error on expired token", args{expiredToken, "access"}, true, nil, true, "token is expired"},
		{"return error on wrong issuer", args{invalidIssToken, "access"}, true, nil, true, ""},
		{"return error on wrong aud", args{invalidAudToken, "access"}, true, nil, true, ""},
		{"return error on wrong purpose", args{validToken, "csrf"}, true, nil, true, ""},
		{"return error on unpermitted rokwire token", args{validToken, "access"}, false, nil, true, ""},
		//TODO: Fille <invalid retry token> and <valid token after refresh>
		// {"return error on retry invalid token", args{"<invalid retry token>", "access"}, true, nil, true, "initial token check returned invalid, error on retry"},
		// {"return claims after refresh", args{"<valid token after refresh>", "access"}, true, &tokenauth.Claims{}, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(tt.acceptRokwire, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			got, err := tr.CheckToken(tt.args.token, tt.args.purpose)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.CheckToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && !strings.Contains(err.Error(), tt.errSubstring) {
				t.Errorf("TokenAuth.CheckToken() error = %v, errSubstring %s", err, tt.errSubstring)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TokenAuth.CheckToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenAuth_CheckRequestTokens(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokmetro.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokmetro.com", PubKey: nil}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    *tokenauth.Claims
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(true, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			got, err := tr.CheckRequestTokens(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.CheckRequestTokens() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("TokenAuth.CheckRequestTokens() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTokenAuth_ValidateCsrfTokenClaims(t *testing.T) {
	type args struct {
		accessClaims *tokenauth.Claims
		csrfClaims   *tokenauth.Claims
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := setupTestTokenAuth(true, nil)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			if err := tr.ValidateCsrfTokenClaims(tt.args.accessClaims, tt.args.csrfClaims); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.ValidateCsrfTokenClaims() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_ValidatePermissionsClaim(t *testing.T) {
	type args struct {
		claims              *tokenauth.Claims
		requiredPermissions []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := setupTestTokenAuth(true, nil)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			if err := tr.ValidatePermissionsClaim(tt.args.claims, tt.args.requiredPermissions); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.ValidatePermissionsClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_ValidateScopeClaim(t *testing.T) {
	type args struct {
		claims        *tokenauth.Claims
		requiredScope string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := setupTestTokenAuth(true, nil)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			if err := tr.ValidateScopeClaim(tt.args.claims, tt.args.requiredScope); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.ValidateScopeClaim() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGetRequestTokens(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := tokenauth.GetRequestTokens(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRequestTokens() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRequestTokens() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("GetRequestTokens() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
