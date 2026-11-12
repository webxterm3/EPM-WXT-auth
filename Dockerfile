# ─────────────────────────────────────────────
# Stage 1: Build
# ─────────────────────────────────────────────
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

ARG TARGETOS
ARG TARGETARCH

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags="-s -w" -o vsay-auth ./cmd/server/main.go

# ─────────────────────────────────────────────
# Stage 2: Runtime
# ─────────────────────────────────────────────
FROM --platform=$TARGETPLATFORM alpine:3.21

# Pick up patched versions of every base-image package (e.g. busybox CVEs)
# regardless of how stale the alpine:3.21 tag itself is at build time.
RUN apk --no-cache upgrade && apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/vsay-auth .

# ── Server ────────────────────────────────────
ENV PORT=8081
ENV ENVIRONMENT=production
ENV GIN_MODE=release

# ── Keycloak ──────────────────────────────────
ENV KEYCLOAK_URL=http://keycloak:8080
ENV KEYCLOAK_REALM=master
ENV KEYCLOAK_CLIENT_ID=vsay-auth
ENV KEYCLOAK_CLIENT_SECRET=""
ENV KEYCLOAK_ADMIN_USERNAME=admin
ENV KEYCLOAK_ADMIN_PASSWORD=""

# ── Super Admin ───────────────────────────────
ENV SUPER_ADMIN_USERNAME=superadmin
ENV SUPER_ADMIN_EMAIL=""
ENV SUPER_ADMIN_PASSWORD=""

# ── MongoDB ───────────────────────────────────
ENV MONGO_URI=""
ENV MONGO_DATABASE=vsay-auth

# ── Backend / Proxy ───────────────────────────
ENV VSAY_AGENT_BACKEND_URL=http://vsay-backend:8082
ENV WXT_LOG_MANAGER_URL=http://localhost:8090
ENV BACKEND_PROXY_PREFIX=/api
ENV VSAY_TUNNEL_URL=http://localhost:8083
ENV GATEWAY_SECRET=""

# ── JWT ───────────────────────────────────────
ENV JWT_SECRET=""
ENV JWT_EXPIRY_HOURS=24

# ── Email / SMTP ──────────────────────────────
ENV SMTP_HOST=smtp.gmail.com
ENV SMTP_PORT=587
ENV SMTP_USERNAME=""
ENV SMTP_PASSWORD=""
ENV SMTP_FROM=""

# ── OTP ───────────────────────────────────────
ENV OTP_ENABLED=false
ENV OTP_EXPIRY_MINUTES=10

# ── Reconciler ────────────────────────────────
ENV RECONCILER_INTERVAL_MINUTES=5

# ── CORS / Frontend ───────────────────────────
ENV ALLOWED_ORIGINS=http://localhost:3000
ENV FRONTEND_URL=http://localhost:3000

# ── OIDC / Social Login ───────────────────────
ENV MICROSOFT_CLIENT_ID=""
ENV MICROSOFT_CLIENT_SECRET=""
ENV MICROSOFT_TENANT_ID=common
ENV GITHUB_CLIENT_ID=""
ENV GITHUB_CLIENT_SECRET=""
ENV OIDC_REDIRECT_BASE_URL=http://localhost:8081

ENV LICENSE_TOKEN=XER7AxLBzr_McwKl8YzfQIQ9AOx-mHJFmO6ZIif5gHaMnma7ECfdkqJ8S0IFs3bcqwlpr8Px30ctsqKpFv34joAjFSB5WEKCn_hRl6if-w4qISObosNQamDTZeNRPjCZOaqTyHbI_0jLVNuff484fRqP4_yUjvCcXfifsLOFAJ26mJOuslfUHh3giMLm6s5_aA3d0SFgwcenrB0BWAQgYsFps6k72z5vqgh5jQg068VzGBO8qJxOCzl89FNmFIf_1jrqSTLss1S-VHuWzNNrfKBBh4HUiiks8l2mJEk07p2ZRKi-rUIgy9SOui_mwAdfFWCHWziPO8FC_HLBzpcp1s-olvrRPh4_10pQXYtbPkHOpLil0kDU.h3G_-4MkvrEngTcGMZ04FjWArkrH-MSRPPb1J5B4P8cFlTUxDtQzXWhDSEVvTwyLKu5Bq4xoEWL2yE_XY7-HBw
ENV LICENSE_PUBLIC_KEY=rBMKelblFYjeJRB68ZShPr25fW2gy5Yf4AThD23FR34=
ENV LICENSE_ENCRYPT_KEY=gJy7AE2RJdYpGbjSqQOYXtBfjadMtz37tS0BgayX4Is=

EXPOSE 8081

ENTRYPOINT ["./vsay-auth"]
