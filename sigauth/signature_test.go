package sigauth_test

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authservice/mocks"
	"github.com/rokmetro/auth-library/internal/testutils"
	"github.com/rokmetro/auth-library/sigauth"
)

func setupTestSignatureAuth(mockLoader *mocks.ServiceRegLoader) (*sigauth.SignatureAuth, error) {
	auth, err := testutils.SetupTestAuthService(mockLoader)
	if err != nil {
		return nil, fmt.Errorf("error setting up test auth service: %v", err)
	}
	return sigauth.NewSignatureAuth(testutils.GetSamplePrivKey(), auth)
}

func TestSignatureAuth_Sign(t *testing.T) {
	type args struct {
		message []byte
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := setupTestSignatureAuth(nil)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			got, err := s.Sign(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignatureAuth.Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureAuth_CheckSignature(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokmetro.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokmetro.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		serviceID string
		message   []byte
		signature string
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
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			s, err := setupTestSignatureAuth(mockLoader)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			if err := s.CheckSignature(tt.args.serviceID, tt.args.message, tt.args.signature); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuth_SignRequest(t *testing.T) {
	type args struct {
		r *http.Request
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
			s, err := setupTestSignatureAuth(nil)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			if err := s.SignRequest(tt.args.r); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.SignRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuth_CheckRequestSignature(t *testing.T) {
	testServiceReg := authservice.ServiceReg{ServiceID: "test", Host: "https://test.rokmetro.com", PubKey: nil}
	authServiceReg := authservice.ServiceReg{ServiceID: "auth", Host: "https://auth.rokmetro.com", PubKey: testutils.GetSamplePubKey()}
	serviceRegsValid := []authservice.ServiceReg{authServiceReg, testServiceReg}
	subscribed := []string{"auth"}

	type args struct {
		r                  *http.Request
		requiredServiceIDs []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockLoader := testutils.SetupMockServiceLoader(subscribed, serviceRegsValid, nil)
			s, err := setupTestSignatureAuth(mockLoader)
			if err != nil || s == nil {
				t.Errorf("Error initializing test signature auth: %v", err)
				return
			}
			got, err := s.CheckRequestSignature(tt.args.r, tt.args.requiredServiceIDs)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuth.CheckRequestSignature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignatureAuth.CheckRequestSignature() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildSignatureString(t *testing.T) {
	type args struct {
		r       *http.Request
		headers []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.BuildSignatureString(tt.args.r, tt.args.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("BuildSignatureString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("BuildSignatureString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRequestLine(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sigauth.GetRequestLine(tt.args.r); got != tt.want {
				t.Errorf("GetRequestLine() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetRequestDigest(t *testing.T) {
	type args struct {
		r *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.GetRequestDigest(tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetRequestDigest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("GetRequestDigest() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSignatureAuthHeader_SetField(t *testing.T) {
	type args struct {
		field string
		value string
	}
	tests := []struct {
		name    string
		s       *sigauth.SignatureAuthHeader
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.s.SetField(tt.args.field, tt.args.value); (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuthHeader.SetField() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestSignatureAuthHeader_Build(t *testing.T) {
	tests := []struct {
		name    string
		s       *sigauth.SignatureAuthHeader
		want    string
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.Build()
			if (err != nil) != tt.wantErr {
				t.Errorf("SignatureAuthHeader.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SignatureAuthHeader.Build() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseSignatureAuthHeader(t *testing.T) {
	type args struct {
		header string
	}
	tests := []struct {
		name    string
		args    args
		want    *sigauth.SignatureAuthHeader
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := sigauth.ParseSignatureAuthHeader(tt.args.header)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseSignatureAuthHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParseSignatureAuthHeader() = %v, want %v", got, tt.want)
			}
		})
	}
}
