package authorization

import (
	"testing"

	"github.com/casbin/casbin/v2"
)

var (
	permissionAuth = NewCasbinAuthorization("./test_permissions_authorization_policy.csv")
	scopeAuth = NewCasbinAuthorization("./test_scope_authorization_policy.csv")
)

func TestCasbinAuthorization_Any(t *testing.T) {
	type args struct {
		values []string
		object string
		action string
	}
	tests := []struct {
		name     string
		enforcer *casbin.Enforcer
		args     args
		wantErr  bool
	}{
		{"test_permission_casbin_admin_get", permissionAuth.enforcer, args{[]string{"admin", "test"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_admin_post", permissionAuth.enforcer, args{[]string{"admin", "test"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_lite_admin", permissionAuth.enforcer, args{[]string{"lite_admin", "test"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_lite_admin_no_access", permissionAuth.enforcer, args{[]string{"lite_admin", "test"}, "/admin/test", "DELETE"}, true},

		{"test_scope_casbin", scopeAuth.enforcer, args{[]string{"sample:read:test"}, "/test", "GET"}, false},
		{"test_scope_casbin_no_access", scopeAuth.enforcer, args{[]string{"sample:read:test", "test"}, "/test", "PUT"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CasbinAuthorization{
				enforcer: tt.enforcer,
			}
			if err := c.Any(tt.args.values, tt.args.object, tt.args.action); (err != nil) != tt.wantErr {
				t.Errorf("CasbinAuthorization.Any() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCasbinAuthorization_All(t *testing.T) {
	type args struct {
		values []string
		object string
		action string
	}
	tests := []struct {
		name     string
		enforcer *casbin.Enforcer
		args     args
		wantErr  bool
	}{
		{"test_permission_casbin_admin_get", permissionAuth.enforcer, args{[]string{"admin"}, "/admin/test", "GET"}, false},
		{"test_permission_casbin_admin_fail", permissionAuth.enforcer, args{[]string{"admin", "test"}, "/admin/test", "GET"}, true},
		{"test_permission_casbin_lite_admin", permissionAuth.enforcer, args{[]string{"lite_admin", "test"}, "/admin/test", "GET"}, true},

		{"test_scope_casbin", scopeAuth.enforcer, args{[]string{"sample:read:test"}, "/test", "GET"}, false},
		{"test_scope_casbin_no_access", scopeAuth.enforcer, args{[]string{"sample:read:test", "test"}, "/test", "PUT"}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &CasbinAuthorization{
				enforcer: tt.enforcer,
			}
			if err := c.All(tt.args.values, tt.args.object, tt.args.action); (err != nil) != tt.wantErr {
				t.Errorf("CasbinAuthorization.All() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
