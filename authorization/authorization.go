package authorization

import (
	"fmt"

	"github.com/casbin/casbin"
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
		if c.enforcer.Enforce(value, object, action) {
			return nil
		}
	}

	return fmt.Errorf("Access control error: trying to apply %s operation for %s", action, object)
}

// All will validate that if the casbin enforcer gives access to all the provided values
//	Returns nil on success and error on failure.
func (c *CasbinAuthorization) All(values []string, object string, action string) error {
	for _, value := range values {
		if !c.enforcer.Enforce(value, object, action) {
			return fmt.Errorf("Access control error: %s is trying to apply %s operation for %s", value, action, object)
		}
	}

	return nil
}
