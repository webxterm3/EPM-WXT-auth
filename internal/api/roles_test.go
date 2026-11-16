package api

import (
	"testing"

	"github.com/vsay/vsay-auth/internal/middleware"
)

// AssignUserRoles validates the requested role against this list, so a role
// that is missing from it cannot be assigned at all — the request comes back
// "Invalid portal role".
//
// That failure is quiet in the place it matters: the group page adds the
// person first and assigns the role second, so a missing entry here shows up
// as "added to the group, but the role was not changed" and nothing says why.
func TestEveryAssignableRoleIsListed(t *testing.T) {
	want := map[string]bool{
		middleware.RoleSuperAdmin:   true,
		middleware.RoleCompanyAdmin: true,
		middleware.RoleUser:         true,
		middleware.RoleViewer:       true,
	}

	got := map[string]bool{}
	for _, r := range portalRoles {
		got[r.ID] = true
	}

	for id := range want {
		if !got[id] {
			t.Errorf("%q is not in portalRoles, so it cannot be assigned to anybody", id)
		}
	}
	for id := range got {
		if !want[id] {
			t.Errorf("portalRoles offers %q, which is not a role this system defines", id)
		}
	}
}

// Every role needs a description: the picker shows it, and a role whose
// meaning is blank is one an administrator assigns by guessing.
func TestEveryRoleSaysWhatItIs(t *testing.T) {
	for _, r := range portalRoles {
		if r.DisplayName == "" {
			t.Errorf("role %q has no display name", r.ID)
		}
		if r.Description == "" {
			t.Errorf("role %q has no description", r.ID)
		}
	}
}

// The Viewer's listed permissions must not include acting on anything. The
// list is what the roles screen shows, so a stray "use_assigned_machines"
// there would describe the role as something it is not.
func TestTheViewerIsNotDescribedAsBeingAbleToAct(t *testing.T) {
	for _, r := range portalRoles {
		if r.ID != middleware.RoleViewer {
			continue
		}
		for _, p := range r.Permissions {
			switch p {
			case "use_assigned_machines", "manage_users", "manage_groups",
				"manage_machines", "system_configuration", "manage_organizations",
				"manage_all_users", "manage_all_groups", "manage_all_machines":
				t.Errorf("the Viewer role lists %q, which says it can act", p)
			}
		}
		return
	}
	t.Fatal("the Viewer role is not in portalRoles")
}
