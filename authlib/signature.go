package authlib

import (
	"crypto/rsa"
	"errors"
)

// TokenAuth contains configurations and helper functions required to validate tokens
type SignatureAuth struct {
	authService AuthService
	serviceKey  *rsa.PrivateKey
}

// SignMessage generates and returns a signature for the provided message
func (a *SignatureAuth) SignMessage(message string) (string, error) {
	// TODO: Implement
	return "", errors.New("Unimplemented")
}

// CheckAccessToken validates the provided message signature
func (a *SignatureAuth) CheckSignature(message string, signature string) (map[string]interface{}, error) {
	// TODO: Implement
	return nil, errors.New("Unimplemented")
}
