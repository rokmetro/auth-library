package authutils

import (
	"crypto/sha256"
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

// GetKeyFingerprint returns the fingerprint for a given PEM encoded key
func GetKeyFingerprint(keyPem string) (string, error) {
	key, rest := pem.Decode([]byte(keyPem))
	if len(rest) != 0 || key == nil || len(key.Bytes) == 0 {
		return "", errors.New("failed to decode key with pem")
	}

	hash, err := HashSha256(key.Bytes)
	if err != nil {
		return "", fmt.Errorf("error hashing key: %v", err)
	}

	return base64.StdEncoding.EncodeToString(hash), nil
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