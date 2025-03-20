package rbac_test

import (
	"testing"
	"time"

	"github.com/acudac-com/rbac-go"
)

var Rbac *rbac.Rbac

func init() {
	authChain := rbac.Chain("auth")
	authChain.Add("Unauthenticated", []string{
		"list",
	})
	authChain.Add("Authenticated", []string{
		"create",
	})

	accountChain := rbac.Chain("use.Account")
	accountChain.Add("Member", []string{
		"get",
	})
	accountChain.Add("Admin", []string{
		"update",
		"delete",
	})

	var err error
	Rbac, err = rbac.NewRbac(authChain, accountChain)
	if err != nil {
		panic(err)
	}
}

func Test_HasPermission(t *testing.T) {
	az := Rbac.Authorizer()
	az.AddAsync(func() ([]string, error) {
		time.Sleep(1 * time.Second)
		return []string{"use.Account.Member"}, nil
	})
	if err := az.Err(); err != nil {
		t.Fatal(err)
	}

	if !az.HasPermission("get") {
		t.Fatal("should have get permission")
	}
	if az.HasPermission("update") {
		t.Fatal("should not have update permission")
	}
}

func Test_ChainHasRoleId(t *testing.T) {
	result := Rbac.ChainHasRoleId("use.Account", "Member")
	if !result {
		t.Fatal("should have Member role")
	}
}
