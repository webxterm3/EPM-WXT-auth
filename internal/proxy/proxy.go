package proxy

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.uber.org/zap"
)

type Proxy struct {
	backendURL    *url.URL
	proxy         *httputil.ReverseProxy
	logger        *zap.Logger
	gatewaySecret string
}

// NewProxy creates a new proxy to the backend
func NewProxy(backendURL string, gatewaySecret string, logger *zap.Logger) (*Proxy, error) {
	parsedURL, err := url.Parse(backendURL)
	if err != nil {
		return nil, err
	}

	// Extract base path from backend URL (e.g., "/api" from "http://localhost:8080/api")
	basePath := parsedURL.Path
	if basePath == "" {
		basePath = "/"
	}

	// Create a target URL with just the host (no path)
	targetURL := &url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
	}
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Customize director to add user context headers and preserve base path
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Set the host to the backend URL
		req.Host = parsedURL.Host
		req.URL.Host = parsedURL.Host
		req.URL.Scheme = parsedURL.Scheme

		// Prepend the base path to the request path
		// e.g., if request is /machines and basePath is /api, final path is /api/machines
		if basePath != "/" {
			req.URL.Path = basePath + req.URL.Path
		}
	}

	// Customize error handler
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		logger.Error("Proxy error",
			zap.String("url", r.URL.String()),
			zap.Error(err))
		w.WriteHeader(http.StatusBadGateway)
		if _, writeErr := w.Write([]byte(`{"error": "Backend service unavailable"}`)); writeErr != nil {
			logger.Warn("Failed to write proxy error response", zap.Error(writeErr))
		}
	}

	return &Proxy{
		backendURL:    parsedURL,
		proxy:         proxy,
		logger:        logger,
		gatewaySecret: gatewaySecret,
	}, nil
}

// Handler returns a Gin handler that proxies requests to the backend
func (p *Proxy) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Logging removed - requests are already logged in audit middleware and stored in DB

		// Add gateway authentication token (internal service communication)
		c.Request.Header.Set("X-Gateway-Token", p.gatewaySecret)

		// Add user context as custom headers for the backend
		if userID, exists := c.Get("user_id"); exists {
			// Handle both string and ObjectID types
			var userIDStr string
			switch v := userID.(type) {
			case string:
				userIDStr = v
			case primitive.ObjectID:
				userIDStr = v.Hex()
			default:
				p.logger.Warn("Unexpected user_id type", zap.Any("type", v))
				userIDStr = ""
			}
			if userIDStr != "" {
				c.Request.Header.Set("X-User-ID", userIDStr)
			}
		}
		if username, exists := c.Get("username"); exists {
			c.Request.Header.Set("X-Username", username.(string))
		}
		if email, exists := c.Get("email"); exists {
			c.Request.Header.Set("X-User-Email", email.(string))
		}
		if tenantID, exists := c.Get("tenant_id"); exists {
			c.Request.Header.Set("X-Tenant-ID", tenantID.(string))
		}
		if tenantName, exists := c.Get("tenant_name"); exists {
			c.Request.Header.Set("X-Tenant-Name", tenantName.(string))
		}
		if role, exists := c.Get("role"); exists {
			c.Request.Header.Set("X-User-Role", role.(string))
		}
		if machineRole, exists := c.Get("machine_role"); exists {
			c.Request.Header.Set("X-Machine-Role", machineRole.(string))
		}
		if groups, exists := c.Get("groups"); exists {
			// Convert groups array to comma-separated string
			groupsStr := strings.Join(groups.([]string), ",")
			c.Request.Header.Set("X-User-Groups", groupsStr)
		}
		if keycloakID, exists := c.Get("keycloak_id"); exists {
			c.Request.Header.Set("X-Keycloak-ID", keycloakID.(string))
		}
		if source, exists := c.Get("source"); exists {
			c.Request.Header.Set("X-Source", source.(string))
		}

		// Check if this is a WebSocket upgrade request
		isWebSocket := c.GetHeader("Upgrade") == "websocket" && c.GetHeader("Connection") == "Upgrade"

		if isWebSocket {
			p.logger.Info("WebSocket upgrade request",
				zap.String("path", c.Request.URL.Path),
				zap.String("user_id", c.Request.Header.Get("X-User-ID")),
				zap.String("username", c.Request.Header.Get("X-Username")))
		} else {
			// Log the proxied request
			p.logger.Debug("Proxying request",
				zap.String("method", c.Request.Method),
				zap.String("path", c.Request.URL.Path),
				zap.String("backend", p.backendURL.String()))
		}

		// Proxy the request
		p.proxy.ServeHTTP(c.Writer, c.Request)
	}
}

// HealthCheckHandler checks if the backend is healthy
func (p *Proxy) HealthCheckHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Try to connect to backend health endpoint
		healthURL := p.backendURL.String() + "/health"
		resp, err := http.Get(healthURL) // #nosec G107 -- backendURL is server config (env var), not user input
		if err != nil {
			p.logger.Error("Backend health check failed", zap.Error(err))
			c.JSON(http.StatusServiceUnavailable, gin.H{
				"backend": "unhealthy",
				"error":   err.Error(),
			})
			return
		}
		defer resp.Body.Close()

		// Read response body
		body, _ := io.ReadAll(resp.Body)

		c.JSON(resp.StatusCode, gin.H{
			"backend": "healthy",
			"status":  resp.StatusCode,
			"body":    string(body),
		})
	}
}

// RegisterPublicProxyRoutes registers backend routes that do NOT require JWT auth.
// These are root-level routes on the backend (no /api prefix) with their own auth mechanism.
func RegisterPublicProxyRoutes(r *gin.Engine, proxy, logProxy *Proxy) {
	// GET /server-cert — agents download server cert for TLS pinning (self-signed setups)
	r.GET("/server-cert", proxy.Handler())

	// POST /agent/sign-cert — agents submit CSR to get CA-signed client cert (Bearer token auth)
	r.POST("/agent/sign-cert", proxy.Handler())

	// GET /ca-cert — agents download the private CA cert for mTLS trust pinning
	r.GET("/ca-cert", proxy.Handler())

	// GET /ca-fingerprint — agents poll this to detect CA rotation (no auth needed)
	r.GET("/ca-fingerprint", proxy.Handler())

	// GET /agent/download/:filename — agent package downloads (no auth, public)
	r.GET("/agent/download/:filename", proxy.Handler())
	// GET /agent/install-macos.sh — the macOS terminal installer, piped into
	// bash. Public for the same reason the packages are: it runs before a
	// machine has any credentials.
	r.GET("/agent/install-macos.sh", proxy.Handler())

	// POST /agent/logs — agents ship the MACHINE's own system logs and website
	// activity as gzipped NDJSON batches. Public for the same reason as
	// sign-cert: the caller is an agent holding its registration token, not a
	// portal user with a session. The log manager authenticates that token
	// and rejects revoked machines.
	//
	// Sent STRAIGHT to the log manager, not through the backend.
	//
	// The backend can forward these and does, for agents enrolled against it
	// directly. But an agent enrolled against this gateway would then make
	// three hops before anything reaches storage — gateway, backend, log
	// manager — inside the fifteen seconds the agent gives one upload. It
	// did not fit: uploads timed out with "Client.Timeout exceeded while
	// awaiting headers", the agent kept the batch and retried, and the
	// backlog grew faster than it drained.
	//
	// Nothing on the backend's hop was doing any work. It read none of the
	// body and made no decision; it only copied bytes. Taking it out
	// restores the hop count the fleet had before log collection moved, and
	// leaves the backend out of a path it has no part in.
	if logProxy != nil {
		r.POST("/agent/logs", logProxy.Handler())
	} else {
		r.POST("/agent/logs", proxy.Handler())
	}

	// NOTE: /grpc-mode is registered directly in main.go with its own fallback logic
}

// NewTunnelProxy creates a proxy to the vsay-tunnel service.
// Returns nil if tunnelURL is empty (feature disabled).
func NewTunnelProxy(tunnelURL string, gatewaySecret string, logger *zap.Logger) (*Proxy, error) {
	if tunnelURL == "" {
		return nil, nil
	}
	return NewProxy(tunnelURL, gatewaySecret, logger)
}

// tunnelDisabledHandler returns 503 when vsay-tunnel is not configured.
func tunnelDisabledHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(503, gin.H{"error": "tunnel service not configured — set VSAY_TUNNEL_URL in vsay-auth to enable"})
	}
}

// RegisterTunnelProxyRoutes registers /api/deployments/* routes.
// If tunnelProxy is nil, all routes return 503.
func RegisterTunnelProxyRoutes(r *gin.RouterGroup, tunnelProxy *Proxy, authMiddleware gin.HandlerFunc) {
	if tunnelProxy == nil {
		disabled := tunnelDisabledHandler()
		r.GET("/deployments", authMiddleware, disabled)
		r.POST("/deployments", authMiddleware, disabled)
		r.GET("/deployments/check/:subdomain", authMiddleware, disabled)
		r.GET("/deployments/:id", authMiddleware, disabled)
		r.PUT("/deployments/:id/start", authMiddleware, disabled)
		r.PUT("/deployments/:id/stop", authMiddleware, disabled)
		r.DELETE("/deployments/:id", authMiddleware, disabled)
		r.POST("/deployments/:id/custom-domain", authMiddleware, disabled)
		r.DELETE("/deployments/:id/custom-domain", authMiddleware, disabled)
		return
	}
	handlers := []gin.HandlerFunc{authMiddleware, tunnelProxy.Handler()}
	r.GET("/deployments", handlers...)
	r.POST("/deployments", handlers...)
	r.GET("/deployments/check/:subdomain", handlers...)
	r.GET("/deployments/:id", handlers...)
	r.PUT("/deployments/:id/start", handlers...)
	r.PUT("/deployments/:id/stop", handlers...)
	r.DELETE("/deployments/:id", handlers...)
	r.POST("/deployments/:id/custom-domain", handlers...)
	r.DELETE("/deployments/:id/custom-domain", handlers...)
}

// RegisterProxyRoutes registers proxy routes for backend endpoints
// Routes that should be proxied to vsay-agent-backend
// vsay-auth's own routes (/auth, /users, /admin, /groups) are NOT proxied
func RegisterProxyRoutes(r *gin.RouterGroup, proxy *Proxy, authMiddleware gin.HandlerFunc) {
	// Create handler chain: auth first, then proxy
	handlers := []gin.HandlerFunc{authMiddleware, proxy.Handler()}

	// Register all backend routes explicitly (Gin doesn't allow catch-all with existing routes)
	// Machines routes
	r.GET("/machines", handlers...)
	r.POST("/machines", handlers...)
	r.GET("/machines/:id", handlers...)
	r.DELETE("/machines/:id", handlers...)
	r.POST("/machines/:id/command", handlers...)
	r.POST("/machines/:id/access/grant", handlers...)
	r.POST("/machines/:id/access/revoke", handlers...)
	r.GET("/machines/:id/access/users", handlers...)
	r.GET("/machines/by-id/:id", handlers...)
	r.GET("/machines/:id/logs", handlers...)
	r.GET("/machines/:id/logs/search", handlers...)
	r.GET("/machines/:id/sessions", handlers...)
	r.GET("/machines/:id/sessions/active", handlers...)

	// Profile routes
	r.GET("/profile", handlers...)

	// Dashboard routes
	r.GET("/dashboard/stats", handlers...)
	r.GET("/dashboard/recent-machines", handlers...)
	r.GET("/dashboard/recent-activity", handlers...)

	// Session routes
	r.GET("/sessions/:id", handlers...)

	// Terminal routes
	r.GET("/terminal/:agent_id/ws", handlers...) // Fixed: backend expects :agent_id, not :id
	r.GET("/terminal/sessions", handlers...)
	r.DELETE("/terminal/sessions/:id", handlers...)

	// Remote desktop (RDP) WebSocket — Guacamole canvas
	r.GET("/machines/:id/rdp/ws", handlers...)
	// Downloadable .rdp file for a native RDP client (Windows App)
	r.GET("/machines/:id/rdp/file", handlers...)
	// Live remote-desktop sessions on a machine
	r.GET("/machines/:id/desktop/sessions", handlers...)

	// Remote control — joining the user's LIVE session with their consent,
	// as opposed to /rdp/ws above which opens a separate one.
	r.POST("/machines/:id/remote-control/start", handlers...)
	r.GET("/machines/:id/remote-control/status", handlers...)
	r.POST("/machines/:id/remote-control/stop", handlers...)
	r.GET("/machines/:id/remote-control/ws", handlers...)
	// External SSH/RDP access history + active sessions
	r.GET("/machines/:id/access-events", handlers...)

	// Community/Issues routes
	r.GET("/community/issues", handlers...)
	r.POST("/community/issues", handlers...)
	r.GET("/community/issues/:id", handlers...)
	r.PUT("/community/issues/:id", handlers...)
	r.DELETE("/community/issues/:id", handlers...)
	r.POST("/community/issues/:id/fixes", handlers...)
	r.GET("/community/issues/:id/fixes", handlers...)
	r.POST("/community/issues/:id/fixes/:fix_id/like", handlers...)
	r.DELETE("/community/issues/:id/fixes/:fix_id/like", handlers...)
	r.POST("/community/issues/:id/fixes/:fix_id/accept", handlers...)
	r.POST("/community/upload", handlers...)

	// Installed-application inventory — what software is on the fleet.
	// Read-only: the agent reports it, the portal displays it.
	r.GET("/machines/:id/applications", handlers...)
	r.POST("/machines/:id/applications/scan", handlers...)
	r.GET("/applications/catalog", handlers...)
	r.POST("/applications/scan", handlers...)
	r.GET("/applications/machines", handlers...)

	// Application-control policies. Whether they are enforced or only
	// projected is each tenant's own switch, below.
	r.GET("/app-policies", handlers...)
	r.POST("/app-policies", handlers...)
	r.POST("/app-policies/simulate", handlers...)
	r.GET("/app-policies/:id", handlers...)
	r.PUT("/app-policies/:id", handlers...)
	r.DELETE("/app-policies/:id", handlers...)

	// The application-control enforcement switch, and the record of what
	// endpoints did with it.
	r.GET("/app-control/settings", handlers...)
	r.PUT("/app-control/settings", handlers...)
	r.GET("/app-control/events", handlers...)

	// Remote-access policies: who may connect where, when, and how.
	r.GET("/remote-access-policies", handlers...)
	r.POST("/remote-access-policies", handlers...)
	r.GET("/remote-access-policies/:id", handlers...)
	r.PUT("/remote-access-policies/:id", handlers...)
	r.DELETE("/remote-access-policies/:id", handlers...)

	// Endpoint audit events, CSV export and the compliance report. Distinct
	// from /audit-logs above, which is this service's own sign-in and
	// user-management trail.
	r.GET("/audit-events", handlers...)
	r.GET("/audit-events/export", handlers...)
	r.GET("/compliance-report", handlers...)

	// S3 / tenant configuration routes
	r.GET("/config/s3", handlers...)
	r.POST("/config/s3", handlers...)
	r.POST("/config/s3/test", handlers...)

	// Endpoint log collection — the tenant-wide policy for shipping each
	// MACHINE's own system logs and website activity. Still the backend's,
	// because it is a setting the agents are given; the ARCHIVE of what
	// they ship, and of the portal's own logs, belongs to wxt-log-manager.
	r.GET("/config/log-shipping", handlers...)
	r.POST("/config/log-shipping", handlers...)

	// Session recordings routes
	r.GET("/machines/:id/recordings", handlers...)
	r.GET("/recordings/:id/url", handlers...)

	// Groups / machines management
	r.POST("/machines/:id/groups/add", handlers...)
	r.POST("/machines/:id/groups/remove", handlers...)

	// Agent self-update
	r.GET("/machines/:id/update-check", handlers...)
	r.POST("/machines/:id/update", handlers...)

	// Ask one machine to ship its system logs now. The backend owns this —
	// it holds the gRPC stream to the agent — while READING what was shipped
	// belongs to wxt-log-manager.
	// ":id", not ":agent_id". Gin refuses two different wildcard names at
	// the same position and PANICS AT STARTUP — the gateway would not come
	// up at all. The name here is the proxy's; the backend reads its own.
	r.POST("/machines/:id/logs/ship-now", handlers...)

	// Log management has MOVED to wxt-log-manager — see
	// RegisterLogManagerProxyRoutes. Not duplicated here: Gin panics on a
	// second registration of the same path, so leaving these behind would
	// have stopped the gateway starting at all.

	// Access request routes
	r.POST("/access-requests", handlers...)
	r.GET("/access-requests", handlers...) // admin list-all — role gate enforced by vsay-agent-backend
	r.GET("/access-requests/my", handlers...)
	r.GET("/machines/:id/access-requests", handlers...)
	r.GET("/machines/:id/pending-requests-count", handlers...)
	r.POST("/access-requests/:id/approve", handlers...)
	r.POST("/access-requests/:id/reject", handlers...)
	r.POST("/access-requests/:id/revoke", handlers...)

	// Health check for backend
	r.GET("/backend/health", proxy.HealthCheckHandler())
}

// CustomResponseWriter wraps gin.ResponseWriter to capture response
type CustomResponseWriter struct {
	gin.ResponseWriter
	body       *bytes.Buffer
	statusCode int
}

func (w *CustomResponseWriter) Write(b []byte) (int, error) {
	w.body.Write(b)
	return w.ResponseWriter.Write(b)
}

func (w *CustomResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// NewLogManagerProxy builds the proxy to wxt-log-manager.
//
// Optional in the same way the tunnel is: an installation that has not
// deployed the log service should run with the feature switched off rather
// than fail to start, because every other part of the console is unaffected
// by its absence.
func NewLogManagerProxy(logManagerURL string, gatewaySecret string, logger *zap.Logger) (*Proxy, error) {
	if logManagerURL == "" {
		return nil, nil
	}
	return NewProxy(logManagerURL, gatewaySecret, logger)
}

// logManagerDisabledHandler explains the 503 rather than returning a bare one.
//
// The alternative reads as a broken feature. This is a feature that has not
// been deployed, and the difference matters to whoever is looking at it:
// one is a bug report, the other is a line in a configuration file.
func logManagerDisabledHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(503, gin.H{"error": "log manager service not configured — " +
			"set WXT_LOG_MANAGER_URL in vsay-auth to enable endpoint log " +
			"viewing and log retention"})
	}
}

// RegisterLogManagerProxyRoutes registers the endpoint-log routes.
//
// Behind authMiddleware like everything else, which is what populates the
// identity headers the log service reads. Registered even when the service
// is absent, so the console gets a 503 that says why instead of a 404 that
// looks like a missing route.
func RegisterLogManagerProxyRoutes(r *gin.RouterGroup, logProxy *Proxy, authMiddleware gin.HandlerFunc) {
	// Retention moved here from vsay-agent-backend along with the service
	// that performs it. The PATHS are unchanged, so the console sends the
	// same requests it always did and only the upstream differs.
	routes := []struct {
		method, path string
	}{
		{"GET", "/logs/endpoint"},
		{"GET", "/log-management/config"},
		{"POST", "/log-management/config"},
		{"GET", "/log-management/runs"},
		{"POST", "/log-management/test-connection"},
		{"POST", "/log-management/archive-now"},
		{"POST", "/log-management/runs/:run_id/restore"},
	}

	handler := logManagerDisabledHandler()
	if logProxy != nil {
		handler = logProxy.Handler()
	}
	for _, rt := range routes {
		r.Handle(rt.method, rt.path, authMiddleware, handler)
	}
}
