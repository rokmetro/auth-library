package sigauth

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/authutils"
	"gopkg.in/go-playground/validator.v9"
)

// SignatureAuth contains configurations and helper functions required to validate signatures
type SignatureAuth struct {
	authService *authservice.AuthService

	serviceKey *rsa.PrivateKey
}

// Sign generates and returns a signature for the provided message
func (s *SignatureAuth) Sign(message []byte) (string, error) {
	hash, err := authutils.HashSha256(message)
	if err != nil {
		return "", fmt.Errorf("error hashing message: %v", err)
	}

	signature, err := rsa.SignPSS(rand.Reader, s.serviceKey, crypto.SHA256, hash, nil)
	if err != nil {
		return "", fmt.Errorf("error signing message: %v", err)
	}

	sigB64 := base64.StdEncoding.EncodeToString(signature)

	return sigB64, nil
}

// CheckSignature validates the provided message signature from the given service
func (s *SignatureAuth) CheckSignature(serviceID string, message []byte, signature string) error {
	serviceReg, err := s.authService.GetServiceRegWithPubKey(serviceID)
	if err != nil {
		return fmt.Errorf("failed to retrieve service pub key: %v", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("error decoding signature: %v", err)
	}

	hash, err := authutils.HashSha256(message)
	if err != nil {
		return fmt.Errorf("error hashing message: %v", err)
	}

	err = rsa.VerifyPSS(serviceReg.PubKey.Key, crypto.SHA256, hash, sigBytes, nil)
	if err != nil {
		return fmt.Errorf("error verifying signature: %v", err)
	}

	return nil
}

// SignRequest signs and modifies the provided request with the necessary signature parameters
func (s *SignatureAuth) SignRequest(r *http.Request) error {
	digest, err := GetRequestDigest(r)
	if err != nil {
		return fmt.Errorf("unable to build request digest: %v", err)
	}
	r.Header.Set("Digest", digest)

	headers := []string{"request-line", "host", "date", "digest", "content-length"}

	sigAuthHeader := SignatureAuthHeader{KeyId: s.authService.GetServiceID(), Algorithm: "rsa-sha256", Headers: headers}

	sigString, err := BuildSignatureString(r, headers)
	if err != nil {
		return fmt.Errorf("error building signature string: %v", err)
	}

	sig, err := s.Sign([]byte(sigString))
	if err != nil {
		return fmt.Errorf("error signing signature string: %v", err)
	}

	sigAuthHeader.Signature = sig

	authHeader, err := sigAuthHeader.Build()
	if err != nil {
		return fmt.Errorf("error building authorization header: %v", err)
	}

	r.Header.Set("Authorization", authHeader)

	return nil
}

// CheckRequestSignature validates the signature on the provided request
// 	The request must be signed by one of the services in requiredServiceIDs. If nil, any valid signature
//	from a subscribed service will be accepted
// 	Returns the service ID of the signing service
func (s *SignatureAuth) CheckRequestSignature(r *http.Request, requiredServiceIDs []string) (string, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return "", errors.New("request missing authorization header")
	}

	digestHeader := r.Header.Get("Digest")

	digest, err := GetRequestDigest(r)
	if err != nil {
		return "", fmt.Errorf("unable to build request digest: %v", err)
	}

	if digest != digestHeader {
		return "", errors.New("message digest does not match digest header")
	}

	sigAuthHeader, err := ParseSignatureAuthHeader(authHeader)
	if err != nil {
		return "", fmt.Errorf("error parsing signature authorization header: %v", err)
	}

	if sigAuthHeader.Algorithm != "rsa-sha256" {
		return "", fmt.Errorf("signing algorithm (%s) does not match rsa-sha256", sigAuthHeader.Algorithm)
	}

	if requiredServiceIDs != nil && !authutils.ContainsString(requiredServiceIDs, sigAuthHeader.KeyId) {
		return "", fmt.Errorf("request signer (%s) is not one of the required services %v", sigAuthHeader.KeyId, requiredServiceIDs)
	}

	sigString, err := BuildSignatureString(r, sigAuthHeader.Headers)
	if err != nil {
		return "", fmt.Errorf("error building signature string: %v", err)
	}

	err = s.CheckSignature(sigAuthHeader.KeyId, []byte(sigString), sigAuthHeader.Signature)
	if err != nil {
		return "", fmt.Errorf("error validating signature: %v", err)
	}

	return sigAuthHeader.KeyId, nil
}

// NewSignatureAuth creates and configures a new SignatureAuth instance
func NewSignatureAuth(serviceKey *rsa.PrivateKey, authService *authservice.AuthService) (*SignatureAuth, error) {
	err := authService.ValidateServiceRegistrationKey(serviceKey)
	if err != nil {
		return nil, fmt.Errorf("unable to validate service key registration: please contact the auth service system admin to register a public key for your service - %v", err)
	}

	return &SignatureAuth{serviceKey: serviceKey, authService: authService}, nil
}

// BuildSignatureString builds the string to be signed for the provided request
// 	"headers" specify which headers to include in the signature string
func BuildSignatureString(r *http.Request, headers []string) (string, error) {
	sigString := ""
	for _, header := range headers {
		if sigString != "" {
			sigString += "\n"
		}

		val := ""
		if header == "request-line" {
			val = GetRequestLine(r)
		} else {
			val = header + ": " + r.Header.Get(header)
		}

		if val == "" {
			return "", fmt.Errorf("missing or empty header: %s", header)
		}

		sigString += val
	}

	return sigString, nil
}

// GetRequestLine returns the request line for the provided request
func GetRequestLine(r *http.Request) string {
	return fmt.Sprintf("%s %s %s", r.Method, r.RequestURI, r.Proto)
}

// GetRequestDigest returns the SHA256 digest of the provided request body
func GetRequestDigest(r *http.Request) (string, error) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return "", fmt.Errorf("error reading request body: %v", err)
	}
	r.Body.Close()

	hash, err := authutils.HashSha256(body)
	if err != nil {
		return "", fmt.Errorf("error hashing request body: %v", err)
	}

	return "SHA-256=" + string(hash), nil
}

// -------------------- SignatureAuthHeader --------------------

//SignatureAuthHeader defines the structure of the Authorization header for signature authentication
type SignatureAuthHeader struct {
	KeyId      string   `json:"keyId" validate:"required"`
	Algorithm  string   `json:"algorithm" validate:"required"`
	Headers    []string `json:"headers,omitempty"`
	Extensions string   `json:"extensions,omitempty"`
	Signature  string   `json:"signature" validate:"required"`
}

// SetField sets the provided field to the provided value
func (s *SignatureAuthHeader) SetField(field string, value string) error {
	switch field {
	case "keyId":
		s.KeyId = value
	case "algorithm":
		s.Algorithm = value
	case "headers":
		s.Headers = strings.Split(value, " ")
	case "extensions":
		s.Extensions = value
	case "signature":
		s.Signature = value
	default:
		return fmt.Errorf("invalid field: %s", field)
	}

	return nil
}

// Build builds the signature Authorization header string
func (s *SignatureAuthHeader) Build() (string, error) {
	validate := validator.New()
	err := validate.Struct(s)
	if err != nil {
		return "", fmt.Errorf("error validating signature auth header: %v", err)
	}

	headers := ""
	if s.Headers != nil {
		headers = fmt.Sprintf("headers=\"%s\",", strings.Join(s.Headers, " "))
	}

	extensions := ""
	if s.Extensions != "" {
		extensions = fmt.Sprintf("extensions=\"%s\",", extensions)
	}

	return fmt.Sprintf("Signature keyId=\"%s\",algorithm=\"%s\",%s%ssignature=\"%s\"", s.KeyId, s.Algorithm, headers, extensions, s.Signature), nil
}

// ParseSignatureAuthHeader parses a signature Authorization header string
func ParseSignatureAuthHeader(header string) (*SignatureAuthHeader, error) {
	if !strings.HasPrefix(header, "Signature ") {
		return nil, errors.New("invalid format: missing Signature prefix")
	}
	header = strings.TrimPrefix(header, "Signature ")

	sigHeader := SignatureAuthHeader{}

	for _, param := range strings.Split(header, ",") {
		parts := strings.Split(param, "=")
		if len(parts) < 2 {
			return nil, fmt.Errorf("invalid format for param: %s", param)
		}

		key := parts[0]
		val := parts[1]

		err := sigHeader.SetField(key, val)
		if err != nil {
			return nil, fmt.Errorf("unable to decode param: %v", err)
		}
	}

	return &sigHeader, nil
}
