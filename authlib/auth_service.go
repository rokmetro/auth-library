package authlib

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
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

// -------------------- AuthService --------------------

// AuthService contains the configurations to interface with the auth service
type AuthService struct {
	serviceLoader ServiceRegLoader

	// ID of implementing service
	serviceID string

	services         *syncmap.Map
	servicesUpdated  *time.Time
	servicesLock     *sync.RWMutex
	refreshCacheFreq int
}

// GetServiceID returns the ID of the implementing service
func (a *AuthService) GetServiceID() string {
	return a.serviceID
}

func (a *AuthService) GetServiceReg(serviceID string) (*ServiceReg, error) {
	a.servicesLock.RLock()
	defer a.servicesLock.RUnlock()

	var loadServicesError error
	now := time.Now()
	if a.servicesUpdated == nil || now.Sub(*a.servicesUpdated).Minutes() > float64(a.refreshCacheFreq) {
		a.servicesLock.RUnlock()
		loadServicesError = a.loadServices()
		a.servicesLock.RLock()
	}

	var service ServiceReg

	if a.services == nil {
		return nil, fmt.Errorf("services could not be loaded: %v", loadServicesError)
	}
	itemValue, ok := a.services.Load(serviceID)
	if !ok {
		return nil, fmt.Errorf("service could not be found for id: %s - %v", serviceID, loadServicesError)
	}

	service, ok = itemValue.(ServiceReg)
	if !ok {
		return nil, fmt.Errorf("service could not be parsed for id: %s - %v", serviceID, loadServicesError)
	}

	return &service, loadServicesError
}

func (a *AuthService) setServices(services []ServiceReg) {
	a.servicesLock.Lock()

	a.services = &syncmap.Map{}
	if len(services) > 0 {
		for _, service := range services {
			a.services.Store(service.ServiceID, service)
		}
	}

	a.servicesLock.Unlock()
}

func (a *AuthService) loadServices() error {
	services, loadServicesError := a.serviceLoader.LoadServices()
	if services != nil {
		a.setServices(services)
	}
	return loadServicesError
}

// SetCacheRefreshFreq sets the frequency at which cached key information is refreshed in minutes
// The default value is 720 (12 hours)
func (a *AuthService) SetCacheRefreshFreq(freq int) {
	a.refreshCacheFreq = freq
}

func (a *AuthService) ValidateServiceRegistration(serviceHost string) error {
	service, err := a.GetServiceReg(a.serviceID)
	if err != nil || service == nil {
		return fmt.Errorf("no service registration found with id %s: %v", a.serviceID, err)
	}

	if serviceHost != service.Host {
		return fmt.Errorf("service host (%s) does not match expected value (%s) for id %s", service.Host, serviceHost, a.serviceID)
	}

	return nil
}

func (a *AuthService) ValidateServiceRegistrationKey(privKey *rsa.PrivateKey) error {
	if privKey == nil {
		return errors.New("provided priv key is nil")
	}

	service, err := a.GetServiceReg(a.serviceID)
	if err != nil || service == nil {
		return fmt.Errorf("no service registration found with id %s: %v", a.serviceID, err)
	}

	if service.PubKey == nil {
		return fmt.Errorf("no service pub key registered for id %s", a.serviceID)
	}

	if service.PubKey.Key == nil {
		err = service.PubKey.LoadKeyFromPem()
		if err != nil || service.PubKey.Key == nil {
			return fmt.Errorf("service pub key is invalid for id %s: %v", a.serviceID, err)
		}
	}

	if *service.PubKey.Key != privKey.PublicKey {
		return fmt.Errorf("service pub key does not match for id %s", a.serviceID)
	}

	return nil
}

// NewAuthService creates and configures a new AuthService instance
func NewAuthService(serviceID string, serviceHost string, serviceLoader ServiceRegLoader) (*AuthService, error) {
	auth := &AuthService{serviceLoader: serviceLoader, serviceID: serviceID, refreshCacheFreq: 720}
	err := auth.loadServices()
	if err != nil {
		return nil, fmt.Errorf("error loading services: %v", err)
	}

	err = auth.ValidateServiceRegistration(serviceHost)
	if err != nil {
		return nil, fmt.Errorf("unable to validate service registration: please contact the auth service system admin to register your service - %v", err)
	}

	return auth, nil
}

// -------------------- KeyLoader --------------------

// ServiceRegLoader provides an interface to load the service registrations for specified services
type ServiceRegLoader interface {
	LoadServices() ([]ServiceReg, error)
	SubscribeService(serviceID string)
	UnsubscribeService(serviceID string)
}

type RemoteServiceRegLoaderImpl struct {
	authHost           string   // Remote host of the auth service
	subscribedServices []string // Service registrations to load
	servicesLock       *sync.RWMutex
}

func (r *RemoteServiceRegLoaderImpl) LoadServices() ([]ServiceReg, error) {
	url := fmt.Sprintf("%s/services", r.authHost)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("error formatting request to load services: %v", err)
	}

	r.servicesLock.RLock()
	servicesQuery := strings.Join(r.subscribedServices, ",")
	r.servicesLock.RUnlock()

	q := req.URL.Query()
	q.Add("ids", servicesQuery)
	req.URL.RawQuery = q.Encode()

	// req.Header.Set("ROKWIRE-API-KEY", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error requesting services: %v", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("error loading services: %d - %s", resp.StatusCode, resp.Body)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading body of service response: %v", err)
	}

	var services []ServiceReg
	err = json.Unmarshal(body, &services)
	if err != nil {
		return nil, fmt.Errorf("error on unmarshal service response: %v", err)
	}

	validate := validator.New()
	err = validate.Struct(services)
	if err != nil {
		return nil, fmt.Errorf("error validating service data: %v", err)
	}

	serviceErrors := map[string]error{}
	for _, service := range services {
		err = service.PubKey.LoadKeyFromPem()
		if err != nil {
			serviceErrors[service.ServiceID] = err
		}
	}

	err = nil
	if len(serviceErrors) > 0 {
		err = fmt.Errorf("error loading services: %v", serviceErrors)
	}

	return services, err
}

func (r *RemoteServiceRegLoaderImpl) SubscribeService(serviceID string) {
	r.servicesLock.Lock()
	if !containsString(r.subscribedServices, serviceID) {
		r.subscribedServices = append(r.subscribedServices, serviceID)
	}
	r.servicesLock.Unlock()
}

func (r *RemoteServiceRegLoaderImpl) UnsubscribeService(serviceID string) {
	r.servicesLock.Lock()
	r.subscribedServices = removeString(r.subscribedServices, serviceID)
	r.servicesLock.Unlock()
}

// NewRemoteServiceRegLoader creates and configures a new RemoteServiceRegLoaderImpl instance for the provided auth service host
func NewRemoteServiceRegLoader(authHost string, subscribedServices []string) *RemoteServiceRegLoaderImpl {
	return &RemoteServiceRegLoaderImpl{authHost: authHost, subscribedServices: subscribedServices}
}

// -------------------- ServiceReg --------------------

// ServiceReg represents a service registration record
type ServiceReg struct {
	ServiceID string  `json:"service" validate:"required"`
	Host      string  `json:"host" validate:"required"`
	PubKey    *PubKey `json:"pub_key"`
}

// -------------------- PubKey --------------------

// PubKey represents a public key object including the key and related metadata
type PubKey struct {
	Key    *rsa.PublicKey
	KeyPem string `json:"key_pem" validate:"required"`
	Alg    string `json:"alg" validate:"required"`
}

func (p *PubKey) LoadKeyFromPem() error {
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(p.KeyPem))
	if err != nil {
		return fmt.Errorf("error parsing key string: %v", err)
	}

	p.Key = key

	return nil
}

func (p *PubKey) GetFingerprint() (string, error) {
	return GetKeyFingerprint(p.KeyPem)
}
