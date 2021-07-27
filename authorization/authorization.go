package authorization

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/casbin/casbin/v2"
)

var (
	_, b, _, _ = runtime.Caller(0)
	basepath   = filepath.Dir(b)
)

// Authorization is a standard authorization interface that can be reused by various auth types.
type Authorization interface {
	Any(values []string, object string, action string) error
	All(values []string, object string, action string) error
}

// CasbinAuthorization is a Casbin implementation of the authorization interface.
type CasbinAuthorization struct {
	enforcer *casbin.Enforcer
}

// Any will validate that if the casbin enforcer gives access to one or more of the provided values
//	Returns nil on success and error on failure.
func (c *CasbinAuthorization) Any(values []string, object string, action string) error {
	for _, value := range values {
		if ok, _ := c.enforcer.Enforce(value, object, action); ok {
			return nil
		}
	}

	return fmt.Errorf("access control error: %v trying to apply %s operation for %s", values, action, object)
}

// All will validate that if the casbin enforcer gives access to all the provided values
//	Returns nil on success and error on failure.
func (c *CasbinAuthorization) All(values []string, object string, action string) error {
	for _, value := range values {
		if ok, _ := c.enforcer.Enforce(value, object, action); !ok {
			return fmt.Errorf("access control error: %s is trying to apply %s operation for %s", value, action, object)
		}
	}

	return nil
}

// NewCasbinAuthorization returns a new casbin enforcer
func NewCasbinAuthorization(policyPath string) *CasbinAuthorization {
	enforcer, err := casbin.NewEnforcer(basepath+"/authorization_model.conf", policyPath)
	if err != nil {
		fmt.Printf("NewCasbinAuthorization() -> error: %s\n", err.Error())
	}

	return &CasbinAuthorization{enforcer}
}
