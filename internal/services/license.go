package services

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
)

// LicenseState represents the 3-state machine for license enforcement.
type LicenseState int32

const (
	LicenseOK     LicenseState = 0 // valid — full service
	LicenseGrace  LicenseState = 1 // expired but within 48h emergency window — service works, warnings logged
	LicenseLocked LicenseState = 2 // grace exhausted — all auth/API requests return 503
)

// licensePayload mirrors the portal's LicensePayload struct.
type licensePayload struct {
	LicenseID      string     `json:"license_id"`
	Company        string     `json:"company"`
	Plan           string     `json:"plan"`
	MachineQuota   int        `json:"machine_quota"`
	Status         string     `json:"status"`
	UpdatesGranted bool       `json:"updates_granted"`
	UpdateChannel  string     `json:"update_channel,omitempty"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	IssuedAt       time.Time  `json:"issued_at"`
}

// LicenseInfo is the public read-only view of the loaded license.
type LicenseInfo struct {
	LicenseID    string
	Company      string
	Plan         string
	MachineQuota int
	ExpiresAt    *time.Time
	State        LicenseState
}

// LicenseService loads, verifies, and periodically re-checks the license file.
// It is safe for concurrent use.
type LicenseService struct {
	tokenInline string
	pubKey      ed25519.PublicKey
	encKey      []byte
	logger      *zap.Logger

	mu      sync.RWMutex
	payload *licensePayload
	state   atomic.Int32 // stores LicenseState
}

// NewLicenseService creates and immediately verifies the license.
// licenseToken is the raw token string from LICENSE_TOKEN env var.
// devMode must be LICENSE_DEV_MODE=only-to-run-wxt-in-dev-mode (exact string) to run without a token.
func NewLicenseService(licenseToken, pubKeyB64, encKeyB64 string, devMode bool, logger *zap.Logger) (*LicenseService, error) {
	if licenseToken == "" {
		if devMode {
			logger.Warn("LICENSE_DEV_MODE=only-to-run-wxt-in-dev-mode — license enforcement disabled. Never use in production.")
			return nil, nil //nolint:nilnil // intentional: nil means dev mode, gate is bypassed
		}
		return nil, errors.New("LICENSE_TOKEN is not set — paste the token from the portal, or set LICENSE_DEV_MODE=only-to-run-wxt-in-dev-mode for local dev only")
	}

	if pubKeyB64 == "" {
		return nil, errors.New("LICENSE_PUBLIC_KEY must be set when LICENSE_TOKEN is configured")
	}
	if encKeyB64 == "" {
		return nil, errors.New("LICENSE_ENCRYPT_KEY must be set when LICENSE_TOKEN is configured")
	}

	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("LICENSE_PUBLIC_KEY: invalid Ed25519 public key (got %d bytes, want 32)", len(pubBytes))
	}

	encBytes, err := base64.StdEncoding.DecodeString(encKeyB64)
	if err != nil || len(encBytes) != 32 {
		return nil, fmt.Errorf("LICENSE_ENCRYPT_KEY: invalid AES-256 key (got %d bytes, want 32)", len(encBytes))
	}

	svc := &LicenseService{
		tokenInline: licenseToken,
		pubKey:      ed25519.PublicKey(pubBytes),
		encKey:      encBytes,
		logger:      logger,
	}

	if err := svc.load(); err != nil {
		return nil, fmt.Errorf("license check failed on startup: %w", err)
	}

	return svc, nil
}

// Start runs the hourly re-check loop. Call it in a goroutine.
// Dropping a new license file is enough to unlock — no restart required.
func (s *LicenseService) Start(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.load(); err != nil {
				s.logger.Error("license: periodic re-check failed", zap.Error(err))
			}
		}
	}
}

// State returns the current license state (ok / grace / locked).
func (s *LicenseService) State() LicenseState {
	return LicenseState(s.state.Load())
}

// Info returns a copy of the current license metadata.
func (s *LicenseService) Info() LicenseInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.payload == nil {
		return LicenseInfo{State: LicenseLocked}
	}
	return LicenseInfo{
		LicenseID:    s.payload.LicenseID,
		Company:      s.payload.Company,
		Plan:         s.payload.Plan,
		MachineQuota: s.payload.MachineQuota,
		ExpiresAt:    s.payload.ExpiresAt,
		State:        s.State(),
	}
}

// load verifies the in-memory license token and updates the state machine.
func (s *LicenseService) load() error {
	token := strings.TrimSpace(s.tokenInline)

	p, err := verifyLicenseToken(token, s.pubKey, s.encKey)
	if err != nil {
		return err
	}

	if p.Status != "confirmed" {
		return fmt.Errorf("license status is %q — only confirmed licenses are valid", p.Status)
	}

	now := time.Now().UTC()
	var newState LicenseState
	switch {
	case p.ExpiresAt == nil || now.Before(*p.ExpiresAt):
		newState = LicenseOK
	case now.Before(p.ExpiresAt.Add(48 * time.Hour)):
		newState = LicenseGrace
	default:
		newState = LicenseLocked
	}

	// Update payload first under the mutex, then publish the new state atomically.
	// Readers that observe the new state will always find the matching payload.
	s.mu.Lock()
	s.payload = p
	s.mu.Unlock()
	s.state.Store(int32(newState)) // publish last — state is the visibility fence

	switch newState {
	case LicenseOK:
		exp := "never"
		if p.ExpiresAt != nil {
			exp = p.ExpiresAt.Format(time.RFC3339)
		}
		s.logger.Info("license: OK",
			zap.String("id", p.LicenseID),
			zap.String("company", p.Company),
			zap.String("plan", p.Plan),
			zap.Int("quota", p.MachineQuota),
			zap.String("expires_at", exp),
		)
	case LicenseGrace:
		graceEnd := p.ExpiresAt.Add(48 * time.Hour)
		remaining := time.Until(graceEnd).Round(time.Minute)
		s.logger.Warn("license: GRACE PERIOD ACTIVE — service will lock soon, renew immediately",
			zap.String("id", p.LicenseID),
			zap.String("expired_at", p.ExpiresAt.Format(time.RFC3339)),
			zap.String("locks_at", graceEnd.Format(time.RFC3339)),
			zap.String("time_remaining", remaining.String()),
		)
	case LicenseLocked:
		s.logger.Error("license: LOCKED — grace period exhausted, all auth and API requests will return 503",
			zap.String("id", p.LicenseID),
			zap.String("expired_at", p.ExpiresAt.Format(time.RFC3339)),
			zap.String("action", "contact WebXterm support or portal admin to renew and drop a new license file"),
		)
	}

	return nil
}

// verifyLicenseToken verifies and decrypts a license token.
//
// Token format:
//
//	base64url(nonce[12] || ciphertext+tag) . base64url(ed25519_sig)
//
// Verification order — ALWAYS verify the signature first, then decrypt:
//  1. Decode seg1 from base64url → raw ciphertext bytes
//  2. Verify Ed25519 sig over those RAW BYTES (not the base64url string)
//  3. Decrypt AES-256-GCM
//  4. Parse JSON payload
func verifyLicenseToken(token string, pubKey ed25519.PublicKey, encKey []byte) (*licensePayload, error) {
	dot := strings.LastIndex(token, ".")
	if dot < 0 {
		return nil, errors.New("invalid token: no dot separator")
	}
	seg1 := token[:dot]
	sigB64 := token[dot+1:]

	rawBytes, err := base64.RawURLEncoding.DecodeString(seg1)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext segment: %w", err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("decode signature segment: %w", err)
	}

	// Verify Ed25519 signature over raw ciphertext bytes
	if !ed25519.Verify(pubKey, rawBytes, sigBytes) {
		return nil, errors.New("license signature invalid — token may be tampered or the wrong public key is configured")
	}

	// AES-256-GCM decrypt
	if len(rawBytes) < 12 {
		return nil, errors.New("ciphertext too short to contain nonce")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, fmt.Errorf("aes init: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("gcm init: %w", err)
	}
	plaintext, err := gcm.Open(nil, rawBytes[:12], rawBytes[12:], nil)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w (wrong LICENSE_ENCRYPT_KEY?)", err)
	}

	var p licensePayload
	if err := json.Unmarshal(plaintext, &p); err != nil {
		return nil, fmt.Errorf("parse payload: %w", err)
	}
	return &p, nil
}
