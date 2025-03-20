package rbac

import (
	"fmt"
	"strings"
	"sync"
)

// A role that gives a list of permissions.
type Role struct {
	// The unique id of the role in its chain.
	Id string
	// The list of permissions the role gives.
	Permissions []string
}

// A chain of roles which extend each other's permissions.
type RoleChain struct {
	name        string
	roles       []*Role
	permissions []string
}

// Returns a new chain to add roles which extend each other's permissions.
func Chain(name string) *RoleChain {
	return &RoleChain{
		name:        name,
		permissions: []string{},
	}
}

// Adds a role that extends the permissions of all previously added roles in the chain.
func (c *RoleChain) Add(id string, permissions []string) *RoleChain {
	extendedPermissions := append(c.permissions, permissions...)
	c.roles = append(c.roles, &Role{
		Id:          id,
		Permissions: extendedPermissions,
	})
	c.permissions = extendedPermissions
	return c
}

// A role-based access controller
type Rbac struct {
	permissionToRoleSet map[string]map[string]bool
	chainToRoleIdSet    map[string]map[string]bool
	roleToPermissionSet map[string]map[string]bool
}

// Returns a new role-based access controller made up of the provided role chains.
// The final list of roles are flattened in the format {chainName}.{roleId}.
func NewRbac(roleChains ...*RoleChain) (*Rbac, error) {
	if len(roleChains) == 0 {
		return nil, fmt.Errorf("no role chains provided")
	}
	permissionToRoleSet := map[string]map[string]bool{}
	chainToRoleIdSet := map[string]map[string]bool{}
	roleToPermissionSet := map[string]map[string]bool{}
	for _, chain := range roleChains {
		chainToRoleIdSet[chain.name] = map[string]bool{}
		for _, role := range chain.roles {
			chainToRoleIdSet[chain.name][role.Id] = true
			roleName := chain.name + "." + role.Id
			if _, ok := roleToPermissionSet[roleName]; ok {
				return nil, fmt.Errorf("duplicate role %s", roleName)
			}
			roleToPermissionSet[roleName] = map[string]bool{}
			for _, permission := range role.Permissions {
				if _, ok := permissionToRoleSet[permission]; !ok {
					permissionToRoleSet[permission] = map[string]bool{}
				}
				if _, ok := permissionToRoleSet[permission][roleName]; ok {
					return nil, fmt.Errorf("duplicate permission %s in role %s", permission, roleName)
				}
				permissionToRoleSet[permission][roleName] = true
				roleToPermissionSet[roleName][permission] = true
			}
		}
	}
	return &Rbac{
		permissionToRoleSet: permissionToRoleSet,
		chainToRoleIdSet:    chainToRoleIdSet,
		roleToPermissionSet: roleToPermissionSet,
	}, nil
}

// Returns whether the role id exists in the given chain.
func (r *Rbac) ChainHasRoleId(chain string, roleId string) bool {
	if _, ok := r.chainToRoleIdSet[chain]; !ok {
		return false
	}
	if _, ok := r.chainToRoleIdSet[chain][roleId]; !ok {
		return false
	}
	return true
}

// An authorizer with a list of roles.
type Authorizer struct {
	// The rbac this belongs to.
	rbac *Rbac
	// Added roles.
	roles sync.Map
	// A wait group for any async role additions.
	wg sync.WaitGroup
	// Any errors that occurred during async role additions.
	errors sync.Map
}

// Returns an authorizer to add roles to.
func (r *Rbac) Authorizer(roles ...string) *Authorizer {
	er := &Authorizer{
		rbac:   r,
		roles:  sync.Map{},
		wg:     sync.WaitGroup{},
		errors: sync.Map{},
	}
	er.Add(roles...)
	return er
}

// Directly adds one/more roles.
func (a *Authorizer) Add(roles ...string) {
	for _, role := range roles {
		a.roles.Store(role, true)
	}
}

// Asynchronously adds one/more roles.
func (a *Authorizer) AddAsync(f func() ([]string, error)) {
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		roles, err := f()
		if err != nil {
			a.errors.Store(err.Error(), true)
		}
		for _, role := range roles {
			if _, ok := a.rbac.roleToPermissionSet[role]; !ok {
				a.errors.Store(fmt.Sprintf("role %s not allowed", role), true)
			}
		}
		a.Add(roles...)
	}()
}

// Returns a combined error of all sync and async errors that occurred if any.
func (a *Authorizer) Err() error {
	a.wg.Wait()
	errors := []string{}
	a.errors.Range(func(key, value interface{}) bool {
		errors = append(errors, key.(string))
		return true
	})
	if len(errors) == 0 {
		return nil
	}
	return fmt.Errorf("%s", strings.Join(errors, "; "))
}

// Returns whether one of the roles give the specified permission.
func (a *Authorizer) HasPermission(permission string) bool {
	a.wg.Wait()
	rolesThatGiveAccess := a.rbac.permissionToRoleSet[permission]
	for role := range rolesThatGiveAccess {
		if _, ok := a.roles.Load(role); ok {
			return true
		}
	}
	return false
}

// Returns whether one of the roles are the given role.
func (a *Authorizer) HasRole(role string) bool {
	a.wg.Wait()
	_, ok := a.roles.Load(role)
	return ok
}
