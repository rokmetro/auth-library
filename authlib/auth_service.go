package authlib

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
	"golang.org/x/sync/syncmap"
	"gopkg.in/go-playground/validator.v9"
)

// -------------------- Auth Service --------------------

// AuthService contains the configurations to interface with the auth service
type AuthService struct {
	keyLoader KeyLoader

	pubKeys          *syncmap.Map
	pubKeyUpdated    *time.Time
	pubKeyLock       *sync.RWMutex
	refreshCacheFreq int
}

func (a *AuthService) GetPubKey(service string) (*PubKey, error) {
	a.pubKeyLock.RLock()
	defer a.pubKeyLock.RUnlock()

	var loadKeysError error
	now := time.Now()
	if a.pubKeyUpdated == nil || now.Sub(*a.pubKeyUpdated).Minutes() > float64(a.refreshCacheFreq) {
		a.pubKeyLock.RUnlock()
		loadKeysError = a.loadPubKeys()
		a.pubKeyLock.RLock()
	}

	var key PubKey //to return

	if a.pubKeys == nil {
		return nil, fmt.Errorf("pub keys could not be found - %v", loadKeysError)
	}
	itemValue, ok := a.pubKeys.Load(service)
	if !ok {
		return nil, fmt.Errorf("pub key could not be found for service: %s - %v", service, loadKeysError)
	}

	key, ok = itemValue.(PubKey)
	if !ok {
		return nil, fmt.Errorf("pub key could not be parsed for service: %s - %v", service, loadKeysError)
	}

	return &key, loadKeysError
}

func (a *AuthService) setPubKeys(pubKeys []PubKey) {
	a.pubKeyLock.Lock()

	a.pubKeys = &syncmap.Map{}
	if len(pubKeys) > 0 {
		for _, key := range pubKeys {
			a.pubKeys.Store(key.Service, key)
		}
	}

	a.pubKeyLock.Unlock()
}

func (a *AuthService) loadPubKeys() error {
	pubKeys, loadKeysError := a.keyLoader.LoadPubKeys()
	if pubKeys != nil {
		a.setPubKeys(pubKeys)
	}
	return loadKeysError
}

// SetCacheRefreshFreq sets the frequency at which cached key information is refreshed in minutes
// The default value is 720 (12 hours)
func (a *AuthService) SetCacheRefreshFreq(freq int) {
	a.refreshCacheFreq = freq
}

// NewAuthService creates and configures a new AuthService instance
func NewAuthService(keyLoader KeyLoader) *AuthService {
	auth := &AuthService{keyLoader: keyLoader, refreshCacheFreq: 720}
	auth.loadPubKeys()
	return auth
}

// -------------------- Key Loader --------------------

// KeyLoader provides an interface to load the public keys for specified services
type KeyLoader interface {
	LoadPubKeys() ([]PubKey, error)
}

type RemoteKeyLoaderImpl struct {
	host               string   // Remote host of the auth service
	subscribedServices []string // Service public keys to load
}

func (k *RemoteKeyLoaderImpl) LoadPubKeys() ([]PubKey, error) {
	url := fmt.Sprintf("%s/pubkeys", k.host)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to load pub keys: %v", err)
	}

	servicesQuery := strings.Join(k.subscribedServices, ",")

	q := req.URL.Query()
	q.Add("services", servicesQuery)
	req.URL.RawQuery = q.Encode()

	// req.Header.Set("ROKWIRE-API-KEY", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error requesting pub keys: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error loading pub keys: %d - %s", resp.StatusCode, resp.Body)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of pub keys response: %v", err)
	}

	var pubKeys []PubKey
	err = json.Unmarshal(body, &pubKeys)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal pub keys response: %v", err)
	}

	validate := validator.New()
	err = validate.Struct(pubKeys)
	if err != nil {
		return nil, fmt.Errorf("error validating pub keys data: %v", err)
	}

	serviceErrors := map[string]error{}
	for _, key := range pubKeys {
		err = key.LoadKeyFromString()
		if err != nil {
			serviceErrors[key.Service] = err
		}
	}

	err = nil
	if len(serviceErrors) > 0 {
		err = fmt.Errorf("error loading pub keys: %v", serviceErrors)
	}

	return pubKeys, err
}

// NewRemoteKeyLoader creates and configures a new remoteKeyLoader instance
func NewRemoteKeyLoader(host string, subscribedServices []string) *RemoteKeyLoaderImpl {
	return &RemoteKeyLoaderImpl{host: host, subscribedServices: subscribedServices}
}

// -------------------- Pub Key --------------------

// PubKey represents a public key object including the key and related metadata
type PubKey struct {
	Key     *rsa.PublicKey
	KeyPem  string `json:"key_pem" validate:"required"`
	Service string `json:"service" validate:"required"`
	Kid     string `json:"kid" validate:"required"`
	Issuer  string `json:"iss" validate:"required"`
	Alg     string `json:"alg" validate:"required"`
}

func (k *PubKey) LoadKeyFromString() error {
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(k.KeyPem))
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	k.Key = key
	return nil
}
