package middleware

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// Everything that changes something is refused, whatever it is.
func TestAViewerCannotChangeAnything(t *testing.T) {
	for _, tc := range []struct{ method, route string }{
		{http.MethodPost, "/api/machines/:id/command"},
		{http.MethodPost, "/api/machines/:id/accounts"},
		{http.MethodPost, "/api/machines/:id/account-action"},
		{http.MethodPost, "/api/access-requests/:id/approve"},
		{http.MethodPost, "/api/access-requests/:id/reject"},
		{http.MethodPost, "/api/fleet-config/upgrade-agents"},
		{http.MethodPut, "/api/privilege-policies/:id"},
		{http.MethodPut, "/api/app-control/settings"},
		{http.MethodDelete, "/api/machines/:id"},
		{http.MethodDelete, "/api/app-policies/:id"},
		{http.MethodPatch, "/api/anything"},
	} {
		if ViewerMayCall(tc.method, tc.route) {
			t.Errorf("a viewer may %s %s", tc.method, tc.route)
		}
	}
}

// Reading is the whole point of the role.
func TestAViewerCanRead(t *testing.T) {
	for _, route := range []string{
		"/api/machines",
		"/api/machines/:id",
		"/api/machines/:id/accounts",
		"/api/machines/:id/logs",
		"/api/dashboard/stats",
		"/api/audit-events",
		"/api/audit-events/export",
		"/api/compliance-report",
		"/api/privilege-policies",
		"/api/profile",
	} {
		if !ViewerMayCall(http.MethodGet, route) {
			t.Errorf("a viewer cannot read %s, which is all the role is for", route)
		}
	}
}

// "Read-only" is not "GET only".
//
// A terminal, a remote desktop and a live session takeover are all opened
// with GET, because that is how a WebSocket upgrade works — and each one ends
// with somebody typing on a real machine. Judged by method alone these would
// have been the one category a viewer kept, which is the exact inverse of the
// role.
func TestAViewerCannotOpenASessionOnAMachine(t *testing.T) {
	for _, route := range []string{
		"/api/terminal/:agent_id/ws",
		"/api/machines/:id/rdp/ws",
		"/api/machines/:id/remote-control/ws",
	} {
		if ViewerMayCall(http.MethodGet, route) {
			t.Errorf("a viewer can open %s — that is a keyboard on a managed machine", route)
		}
	}

	// An .rdp file is a set of connection details. Handing it over is handing
	// over the session; it just happens a step later and somewhere this
	// product cannot see.
	if ViewerMayCall(http.MethodGet, "/api/machines/:id/rdp/file") {
		t.Error("a viewer can download an .rdp file, which connects them to the machine")
	}
}

// Signing in and out, and changing one's own password, are not changes to
// anything this product manages. Without these a viewer could not log in at
// all, and could not rotate a password they have reason to think is known.
func TestAViewerCanStillSignInAndOut(t *testing.T) {
	for _, route := range []string{
		"/api/auth/login",
		"/api/auth/logout",
		"/api/auth/refresh",
		"/api/auth/verify-otp",
		"/api/auth/select-tenant",
		"/api/auth/change-password",
	} {
		if !ViewerMayCall(http.MethodPost, route) {
			t.Errorf("a viewer cannot %s, so the role cannot be used at all", route)
		}
	}
}

// A route the router does not recognise is refused rather than allowed.
func TestAnUnmatchedRouteIsRefused(t *testing.T) {
	if ViewerMayCall(http.MethodPost, "") {
		t.Error("an unmatched route is allowed to a viewer")
	}
}

// The self-service list is matched against the ROUTE, so a path value cannot
// be arranged to look like something on it.
func TestAPathValueCannotImpersonateASelfServiceRoute(t *testing.T) {
	for _, route := range []string{
		"/api/machines/:id/command/api/auth/login",
		"/api/auth/login/../../machines/:id/command",
	} {
		if ViewerMayCall(http.MethodPost, route) {
			t.Errorf("%s was treated as self-service", route)
		}
	}
}

// Every mutating route the gateway proxies must be refused to a viewer.
//
// Read from the router rather than listed here: a list would be a copy that
// drifts, and the drift is silent and in the dangerous direction — the new
// route is the one viewers can write.
func TestEveryProxiedMutationIsRefused(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "proxy", "proxy.go"))
	if err != nil {
		t.Fatalf("reading the proxy routes: %v", err)
	}

	routes := regexp.MustCompile(`r\.(GET|POST|PUT|PATCH|DELETE)\("([^"]+)"`).
		FindAllStringSubmatch(string(src), -1)
	if len(routes) < 50 {
		t.Fatalf("found only %d routes; the pattern no longer matches how they are "+
			"registered, so this test is checking nothing", len(routes))
	}

	mutations := 0
	for _, m := range routes {
		method, route := m[1], "/api"+m[2]
		if method == http.MethodGet {
			continue
		}
		mutations++
		if ViewerMayCall(method, route) {
			t.Errorf("a viewer may %s %s", method, route)
		}
	}
	if mutations < 20 {
		t.Errorf("only %d mutating routes were checked, which is too few to be right", mutations)
	}
}

// The guard has to be reached. It is called from AuthMiddleware because that
// is the one function every authenticated route passes through; a check that
// lives anywhere else is a check some route avoids.
func TestTheGuardIsCalledFromEveryAuthenticatedPath(t *testing.T) {
	src, err := os.ReadFile("auth.go")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(src), "GuardReadOnly(c,"); got < 2 {
		t.Errorf("GuardReadOnly is called %d time(s) in auth.go; both the token path "+
			"and the API-key path need it, or a viewer's API key writes freely", got)
	}
}
