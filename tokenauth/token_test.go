package tokenauth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authservice/mocks"
	"github.com/rokmetro/auth-library/internal/testutils"
	"github.com/rokmetro/auth-library/tokenauth"
)

func setupTestTokenAuth(acceptRokwire bool, mockLoader *mocks.ServiceRegLoader) (*tokenauth.TokenAuth, error) {
	auth, err := testutils.SetupTestAuthService(mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	permissionAuth := authorization.NewCasbinAuthorization("./test_permissions_authorization_policy.csv")
	scopeAuth := authorization.NewCasbinAuthorization("./test_scope_authorization_policy.csv")
	return tokenauth.NewTokenAuth(acceptRokwire, auth, permissionAuth, scopeAuth)
}

func getSampleTokenClaims() *tokenauth.Claims {
	return &tokenauth.Claims{
		jwt.StandardClaims{
			Subject:   "test_user_id",
			Audience:  "rokwire",
			ExpiresAt: 0, //TODO: Fill with valid distant future value
			IssuedAt:  0, //TODO: Fill with valid value
		},
		"test_org_id", "access", "example_permission", "rokwire",
	}
}

func TestTokenAuth_CheckToken(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokmetro.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokmetro.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		token   string
		purpose string
	}
	tests := []struct {
		name    string
		args    args
		want    *tokenauth.Claims
		wantErr bool
	}{
		// {"return claims on valid token", args{"", "access"}, getSampleTokenClaims(), false}, //TODO: fill token generated by auth service
		{"return error on valid token", args{"token", "access"}, nil, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(true, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}
			got, err := tr.CheckToken(tt.args.token, tt.args.purpose)
			if (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.CheckToken() error = %v, wantErr %v", err, tt.wantErr)
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

func TestTokenAuth_AuthorizeRequestPermissions(t *testing.T) {
	path := "https://test.rokmetro.com"
	type args struct {
		claims  *tokenauth.Claims
		request *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"test", args{nil, httptest.NewRequest(http.MethodGet, path, nil)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr, err := setupTestTokenAuth(true, nil)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}

			if err := tr.AuthorizeRequestPermissions(tt.args.claims, tt.args.request); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.AuthorizeRequestPermissions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTokenAuth_AuthorizeRequestScope(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokmetro.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokmetro.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	path := "https://test.rokmetro.com"
	type args struct {
		claims  *tokenauth.Claims
		request *http.Request
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
		{"test", args{nil, httptest.NewRequest(http.MethodGet, path, nil)}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			tr, err := setupTestTokenAuth(true, mockLoader)
			if err != nil || tr == nil {
				t.Errorf("Error initializing test token auth: %v", err)
				return
			}

			if err := tr.AuthorizeRequestScope(tt.args.claims, tt.args.request); (err != nil) != tt.wantErr {
				t.Errorf("TokenAuth.AuthorizeRequestScope() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
