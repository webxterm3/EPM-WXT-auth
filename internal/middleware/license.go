package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/services"
	"go.uber.org/zap"
)

// LicenseGate blocks all requests when the EPM license has expired and the
// 48-hour grace period is exhausted.
//
// States:
//   - OK     → request passes through normally
//   - Grace  → request passes through + hourly log warning already emitted by LicenseService
//   - Locked → HTTP 503, login and all API calls are refused until a valid license is loaded
//
// Health, metrics and readiness endpoints are registered on the root router
// (outside the /api group) so they are never affected by this middleware.
func LicenseGate(svc *services.LicenseService, logger *zap.Logger) gin.HandlerFunc {
	// svc == nil means dev/unlicensed mode — no enforcement
	if svc == nil {
		return func(c *gin.Context) { c.Next() }
	}

	return func(c *gin.Context) {
		switch svc.State() {
		case services.LicenseOK:
			c.Next()

		case services.LicenseGrace:
			// Per-request grace log would flood at scale — enforcement warning
			// is already emitted hourly by LicenseService.load(); debug only here.
			logger.Debug("license: grace period — request allowed",
				zap.String("path", c.Request.URL.Path),
			)
			c.Next()

		case services.LicenseLocked:
			info := svc.Info()
			logger.Error("license: LOCKED — request rejected",
				zap.String("id", info.LicenseID),
				zap.String("path", c.Request.URL.Path),
				zap.String("method", c.Request.Method),
			)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error":   "Service is locked — your WebXterm EPM license has expired. Please renew your license and contact support.",
				"code":    "LICENSE_EXPIRED",
				"license": info.LicenseID,
			})

		default:
			// Unknown state — fail closed. Never pass requests through on an
			// unrecognised state; an unknown state is safer blocked than open.
			logger.Error("license: unknown state — request blocked",
				zap.Int("state", int(svc.State())),
				zap.String("path", c.Request.URL.Path),
			)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"error": "License state unknown. Contact support.",
				"code":  "LICENSE_ERROR",
			})
		}
	}
}
