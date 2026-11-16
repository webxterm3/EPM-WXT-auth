package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// A viewer may look at everything an ordinary user can, and change nothing.
//
// # Why this is one check and not a flag on each handler
//
// There are well over a hundred proxied routes and more are added every week.
// A permission expressed per handler is a permission that is correct until
// somebody adds a route and forgets, and the failure is silent and in the
// wrong direction: the new thing is WRITABLE by the people who were not
// supposed to write anything.
//
// So the rule is stated once, in terms of the request rather than the feature:
// a viewer may make a safe request and nothing else. A route added tomorrow is
// denied to viewers before anybody has thought about it, and making it
// available is a deliberate edit to the list below.
//
// # Why the method alone is not enough
//
// "Read-only" is not "GET only". A terminal, a remote desktop and a live
// session takeover are all opened with GET, because that is how a WebSocket
// upgrade works — and every one of them hands somebody a keyboard on a real
// machine. Those are the most consequential things this product does, and by
// method alone they would have been the one category a viewer kept.

// RoleViewer can see what an ordinary user sees and change nothing.
const RoleViewer = "viewer"

// viewerSelfService are the requests a viewer makes about THEMSELVES rather
// than about the estate.
//
// Signing in, signing out and changing one's own password are not changes to
// anything this product manages. Denying them would leave a viewer unable to
// log in at all, and unable to rotate a password they have reason to believe
// is known — which is a worse security position than the one this role exists
// to create.
//
// Matched on the route pattern, not on what the caller typed.
var viewerSelfService = map[string]bool{
	"/api/auth/login":           true,
	"/api/auth/signup":          true,
	"/api/auth/verify-otp":      true,
	"/api/auth/refresh":         true,
	"/api/auth/logout":          true,
	"/api/auth/select-tenant":   true,
	"/api/auth/change-password": true,
}

// ViewerMayCall reports whether a viewer may make this request.
//
// path is the matched ROUTE, "/api/machines/:id/rdp/ws", not the URL the
// caller sent. Matching the route means a path value can never be arranged to
// look like something on a list.
func ViewerMayCall(method, path string) bool {
	if viewerSelfService[path] {
		return true
	}

	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		// Not every GET is a read. A WebSocket upgrade is a GET, and the three
		// this product has — a terminal, a remote desktop, and joining the
		// user's live session — each end with somebody typing on a managed
		// machine. Denied by suffix rather than by name so that the next one
		// added is denied before anybody remembers this file exists.
		if strings.HasSuffix(path, "/ws") {
			return false
		}
		// An .rdp file is a set of connection details: handing it over is
		// handing over the session, it just happens a step later.
		if strings.HasSuffix(path, "/rdp/file") {
			return false
		}
		return true
	default:
		return false
	}
}

// GuardReadOnly refuses a viewer's request if it would change anything.
//
// Returns false when the request was refused, in which case the caller must
// not continue. Called from inside AuthMiddleware, immediately after the role
// is known and before anything else runs, so there is no route in the product
// that can be reached without passing it.
func GuardReadOnly(c *gin.Context, role string, logger *zap.Logger) bool {
	if role != RoleViewer {
		return true
	}

	// FullPath is the registered route. It is empty for a request that matched
	// nothing, and an unmatched request is refused rather than allowed: a
	// viewer has no business being the one to discover a route the router does
	// not know about.
	path := c.FullPath()
	if path == "" {
		path = c.Request.URL.Path
	}

	if ViewerMayCall(c.Request.Method, path) {
		return true
	}

	username, _ := c.Get("username")
	name, _ := username.(string)
	logger.Info("Viewer refused a request that would change something",
		zap.String("username", name),
		zap.String("method", c.Request.Method),
		zap.String("route", path))

	c.JSON(http.StatusForbidden, gin.H{
		"error": "Your account has the Viewer role, which can see this but not change it. " +
			"An administrator can change your role.",
		"role": RoleViewer,
	})
	c.Abort()
	return false
}
