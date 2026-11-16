package entrasync

import (
	"testing"

	"github.com/vsay/vsay-auth/internal/database"
)

// What a directory-synced account is created as when nothing says otherwise.
//
// Viewer, not user, and the reason is the size of a directory. A sync brings
// in everybody an organisation employs, including the people who will never
// open this product. Whatever they land as is what the estate is exposed to
// until somebody reviews a list they did not ask for — so arriving able to
// see and not to act makes that review something an administrator does when
// they get to it, rather than something that has to happen before the next
// sync runs.
func TestAnUnsetDefaultRoleBecomesViewer(t *testing.T) {
	for _, given := range []string{"", "User", "administrator", "viewer-ish", "root"} {
		if got := resolveDefaultRole(given); got != database.RoleViewer {
			t.Errorf("default role %q resolved to %q, want %q", given, got, database.RoleViewer)
		}
	}
}

// A role an administrator actually chose is kept.
func TestAChosenRoleIsKept(t *testing.T) {
	for _, role := range []string{
		database.RoleViewer, database.RoleUser, database.RoleCompanyAdmin, database.RoleSuperAdmin,
	} {
		if got := resolveDefaultRole(role); got != role {
			t.Errorf("default role %q resolved to %q", role, got)
		}
	}
}
