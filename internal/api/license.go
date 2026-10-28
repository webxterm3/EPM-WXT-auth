package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/vsay/vsay-auth/internal/services"
	"go.uber.org/zap"
)

type LicenseHandler struct {
	svc    *services.LicenseService
	logger *zap.Logger
}

func NewLicenseHandler(svc *services.LicenseService, logger *zap.Logger) *LicenseHandler {
	return &LicenseHandler{svc: svc, logger: logger}
}

func RegisterLicenseRoutes(rg *gin.RouterGroup, h *LicenseHandler, authMiddleware gin.HandlerFunc) {
	g := rg.Group("/license", authMiddleware)
	g.GET("/status", h.GetStatus)
}

// GetStatus returns the current license state for the authenticated user.
// All authenticated users can see their own license status — it is not
// admin-only, because end users need to know when the service is about to lock.
func (h *LicenseHandler) GetStatus(c *gin.Context) {
	if h.svc == nil {
		c.JSON(http.StatusOK, gin.H{
			"state":         "dev",
			"state_label":   "Development Mode",
			"enforcement":   false,
			"message":       "License enforcement is disabled (dev mode).",
		})
		return
	}

	info := h.svc.Info()

	stateStr := "ok"
	stateLabel := "Active"
	switch info.State {
	case services.LicenseGrace:
		stateStr = "grace"
		stateLabel = "Grace Period"
	case services.LicenseLocked:
		stateStr = "locked"
		stateLabel = "Locked"
	}

	var expiresAt *string
	var daysRemaining *int
	if info.ExpiresAt != nil {
		s := info.ExpiresAt.UTC().Format(time.RFC3339)
		expiresAt = &s
		days := int(time.Until(*info.ExpiresAt).Hours() / 24)
		daysRemaining = &days
	}

	c.JSON(http.StatusOK, gin.H{
		"license_id":     info.LicenseID,
		"company":        info.Company,
		"plan":           info.Plan,
		"machine_quota":  info.MachineQuota,
		"expires_at":     expiresAt,
		"days_remaining": daysRemaining,
		"state":          stateStr,
		"state_label":    stateLabel,
		"enforcement":    true,
	})
}
