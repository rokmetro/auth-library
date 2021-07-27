package authutils

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

// ContainsString returns true if the provided value is in the provided slice
func ContainsString(slice []string, val string) bool {
	for _, v := range slice {
		if val == v {
			return true
		}
	}
	return false
}

// RemoveString removes the provided value from the provided slice
// 	Returns modified slice. If val is not found returns unmodified slice
func RemoveString(slice []string, val string) ([]string, bool) {
	for i, other := range slice {
		if other == val {
			return append(slice[:i], slice[i+1:]...), true
		}
	}
	return slice, false
}

// GetKeyFingerprint returns the fingerprint for a given rsa.PublicKey
func GetKeyFingerprint(key *rsa.PublicKey) (string, error) {
	if key == nil {
		return "", errors.New("key cannot be nil")
	}
	pubPkcs1 := x509.MarshalPKCS1PublicKey(key)

	hash, err := HashSha256(pubPkcs1)
	if err != nil {
		return "", fmt.Errorf("error hashing key: %v", err)
	}

	return "SHA256:" + base64.StdEncoding.EncodeToString(hash), nil
}

// GetPubKeyPem returns the PEM encoded public key
func GetPubKeyPem(key *rsa.PublicKey) (string, error) {
	if key == nil {
		return "", errors.New("key cannot be nil")
	}

	pemdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: x509.MarshalPKCS1PublicKey(key),
		},
	)

	return string(pemdata), nil
}

// HashSha256 returns the SHA256 hash of the input
func HashSha256(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("cannot hash nil data")
	}

	hasher := sha256.New()
	_, err := hasher.Write(data)
	if err != nil {
		return nil, fmt.Errorf("error writing data: %v", err)
	}
	return hasher.Sum(nil), nil
}
