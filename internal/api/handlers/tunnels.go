package handlers

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/sirupsen/logrus"
	"github.com/unwonone/shipit-server/internal/api/middleware"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/database/sqlc"
	"github.com/unwonone/shipit-server/internal/logger"
)

// TunnelProtocol represents supported tunnel protocols
type TunnelProtocol string

const (
	ProtocolHTTP TunnelProtocol = "http"
	ProtocolTCP  TunnelProtocol = "tcp"
)

// TunnelStatus represents tunnel status
type TunnelStatus string

const (
	StatusActive     TunnelStatus = "active"
	StatusInactive   TunnelStatus = "inactive"
	StatusTerminated TunnelStatus = "terminated"
)

// TunnelHandler handles tunnel-related API endpoints
type TunnelHandler struct {
	db     *database.Database
	config *config.Config
}

// NewTunnelHandler creates a new tunnel handler
func NewTunnelHandler(db *database.Database, config *config.Config) *TunnelHandler {
	return &TunnelHandler{
		db:     db,
		config: config,
	}
}

// CreateTunnelRequest represents a tunnel creation request as per Architecture.md
type CreateTunnelRequest struct {
	Protocol  TunnelProtocol `json:"protocol" binding:"required"`         // "http" or "tcp"
	LocalPort int32          `json:"local_port" binding:"required,min=1"` // Port on client side
	Subdomain *string        `json:"subdomain,omitempty"`                 // Optional custom subdomain
}

// CreateTunnelResponse represents tunnel creation response as per Architecture.md
type CreateTunnelResponse struct {
	TunnelID   string `json:"tunnel_id"`             // UUID of created tunnel
	PublicURL  string `json:"public_url"`            // Public URL for accessing tunnel
	PublicPort *int32 `json:"public_port,omitempty"` // For TCP tunnels only
	Status     string `json:"status"`                // Current status
	Protocol   string `json:"protocol"`              // http or tcp
	CreatedAt  string `json:"created_at"`            // ISO timestamp
}

// TunnelListResponse represents a tunnel in list response
type TunnelListResponse struct {
	TunnelID   string  `json:"tunnel_id"`
	Protocol   string  `json:"protocol"`
	PublicURL  string  `json:"public_url"`
	PublicPort *int32  `json:"public_port,omitempty"`
	Status     string  `json:"status"`
	Subdomain  *string `json:"subdomain,omitempty"`
	LocalPort  int32   `json:"local_port"`
	CreatedAt  string  `json:"created_at"`
	UpdatedAt  string  `json:"updated_at"`
}

// TunnelStatsResponse represents tunnel statistics
type TunnelStatsResponse struct {
	TunnelID          string                 `json:"tunnel_id"`
	ActiveConnections int64                  `json:"active_connections"`
	TotalRequests     int64                  `json:"total_requests"`
	TotalBytesIn      int64                  `json:"total_bytes_in"`
	TotalBytesOut     int64                  `json:"total_bytes_out"`
	Analytics         []TunnelAnalyticsPoint `json:"analytics"`
}

// TunnelAnalyticsPoint represents a single analytics data point
type TunnelAnalyticsPoint struct {
	Timestamp       string  `json:"timestamp"`
	RequestsCount   int64   `json:"requests_count"`
	BytesIn         int64   `json:"bytes_in"`
	BytesOut        int64   `json:"bytes_out"`
	ResponseTimeAvg float32 `json:"response_time_avg"`
	ErrorCount      int64   `json:"error_count"`
}

// IsValid checks if the protocol is valid
func (p TunnelProtocol) IsValid() bool {
	return p == ProtocolHTTP || p == ProtocolTCP
}

// CreateTunnel creates a new tunnel - Control Plane API
func (h *TunnelHandler) CreateTunnel(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	var req CreateTunnelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "Invalid request data",
			"details": err.Error(),
		})
		return
	}

	ctx := c.Request.Context()

	// Validate protocol
	if !req.Protocol.IsValid() {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid protocol. Must be 'http' or 'tcp'",
		})
		return
	}

	// Validate local port
	if req.LocalPort < 1 || req.LocalPort > 65535 {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid local_port. Must be between 1 and 65535",
		})
		return
	}
	// Check user's tunnel limit
	tunnelCount, err := h.db.Queries.CountActiveTunnelsByUser(ctx, userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to check tunnel limit",
		})
		return
	}

	if tunnelCount >= int64(h.config.Tunnels.MaxPerUser) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("Maximum tunnel limit (%d) reached", h.config.Tunnels.MaxPerUser),
		})
		return
	}

	// Generate subdomain and setup tunnel parameters
	var subdomain pgtype.Text
	var publicPort *int32
	var publicURL string

	switch req.Protocol {
	case ProtocolHTTP:
		{
			// Generate subdomain for HTTP tunnels
			subdomainStr := ""
			if req.Subdomain != nil && *req.Subdomain != "" {
				// Validate custom subdomain
				if !isValidSubdomain(*req.Subdomain) {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Invalid subdomain. Must be 3-20 characters, lowercase letters, numbers, and hyphens only",
					})
					return
				}

				// Check if subdomain is available
				if !h.isSubdomainAvailable(ctx, *req.Subdomain) {
					c.JSON(http.StatusConflict, gin.H{
						"error": "Subdomain is already taken",
					})
					return
				}

				subdomainStr = *req.Subdomain
			} else {
				// Generate random subdomain
				subdomainStr = h.generateRandomSubdomain(ctx)
			}
			subdomain.Scan(subdomainStr)
			publicURL = fmt.Sprintf("https://%s.%s", subdomainStr, h.config.Tunnels.DomainHost)

		}
	case ProtocolTCP:
		{
			// Assign a public port for TCP tunnels
			port, err := h.findAvailablePort(ctx)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error": "No available ports for TCP tunnel",
				})
				return
			}
			publicPort = &port
			publicURL = fmt.Sprintf("%s:%d", h.config.Tunnels.DomainHost, port)
		}
	}

	// Set default TTL if not provided
	defaultExpiry := time.Now().Add(h.config.Tunnels.DefaultTTL)
	var pgExpiresAt pgtype.Timestamptz
	pgExpiresAt.Scan(defaultExpiry)

	// Generate tunnel name if not provided
	tunnelName := fmt.Sprintf("%s-tunnel-%s", string(req.Protocol), time.Now().Format("20060102-150405"))

	// Create tunnel in database
	tunnel, err := h.db.Queries.CreateTunnel(ctx, sqlc.CreateTunnelParams{
		UserID:     userID,
		Name:       tunnelName,
		Protocol:   string(req.Protocol),
		Subdomain:  subdomain,
		TargetHost: "localhost", // Client will connect to localhost
		TargetPort: req.LocalPort,
		PublicPort: publicPort,
		Status:     string(StatusActive),
		ExpiresAt:  pgExpiresAt,
	})
	if err != nil {
		logger.WithFields(logrus.Fields{
			"error": err,
			"user_id": userID,
			"tunnel_name": tunnelName,
			"subdomain": subdomain,
			"public_port": publicPort,
			"public_url": publicURL,
			"expires_at": defaultExpiry,
		}).Error("Failed to create tunnel")
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to create tunnel",
		})
		return
	}



	response := CreateTunnelResponse{
		TunnelID:  tunnel.ID.String(),
		PublicURL: publicURL,
		Status:    tunnel.Status,
		Protocol:  tunnel.Protocol,
		CreatedAt: tunnel.CreatedAt.Time.Format(time.RFC3339),
	}

	// Add public port for TCP tunnels
	if tunnel.PublicPort != nil {
		response.PublicPort = tunnel.PublicPort
	}

	c.JSON(http.StatusCreated, response)
}

// ListTunnels lists user's tunnels - Control Plane API
func (h *TunnelHandler) ListTunnels(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	ctx := c.Request.Context()

	// Parse optional query parameters
	status := c.Query("status")
	limitStr := c.DefaultQuery("limit", "50")
	offsetStr := c.DefaultQuery("offset", "0")

	limit, err := strconv.Atoi(limitStr)
	if err != nil || limit <= 0 || limit > 100 {
		limit = 50
	}

	offset, err := strconv.Atoi(offsetStr)
	if err != nil || offset < 0 {
		offset = 0
	}

	// Convert UUID to uuid.UUID
	var pgUserID uuid.UUID
	pgUserID.Scan(userID.String())

	// Get tunnels
	tunnels, err := h.db.Queries.ListTunnelsByUser(ctx, sqlc.ListTunnelsByUserParams{
		UserID: pgUserID,
		Limit:  int32(limit),
		Offset: int32(offset),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to list tunnels",
		})
		return
	}

	// Filter by status if provided
	var filteredTunnels []sqlc.Tunnels
	if status != "" {
		for _, tunnel := range tunnels {
			if tunnel.Status == status {
				filteredTunnels = append(filteredTunnels, tunnel)
			}
		}
	} else {
		filteredTunnels = tunnels
	}

	// Convert to response format
	tunnelList := make([]TunnelListResponse, len(filteredTunnels))
	for i, tunnel := range filteredTunnels {
		tunnelList[i] = h.formatTunnelListResponse(&tunnel)
	}

	c.JSON(http.StatusOK, gin.H{
		"tunnels": tunnelList,
	})
}

// GetTunnel gets a specific tunnel - Control Plane API
func (h *TunnelHandler) GetTunnel(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	tunnelIDStr := c.Param("tunnel_id")

	tunnelID, err := uuid.Parse(tunnelIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	ctx := c.Request.Context()

	// Convert UUIDs to uuid.UUID
	var pgTunnelID uuid.UUID
	pgTunnelID.Scan(tunnelID.String())

	// Get tunnel and verify ownership
	tunnel, err := h.db.Queries.GetTunnelByID(ctx, pgTunnelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	// Verify ownership
	if tunnel.UserID != userID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	response := h.formatTunnelListResponse(&tunnel)
	c.JSON(http.StatusOK, response)
}

// DeleteTunnel terminates a tunnel - Control Plane API
func (h *TunnelHandler) DeleteTunnel(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	tunnelIDStr := c.Param("tunnel_id")
	tunnelID, err := uuid.Parse(tunnelIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	ctx := c.Request.Context()

	// Convert UUIDs to uuid.UUID
	var pgTunnelID, pgUserID uuid.UUID
	pgTunnelID.Scan(tunnelID.String())
	pgUserID.Scan(userID.String())

	// Verify tunnel exists and ownership
	tunnel, err := h.db.Queries.GetTunnelByID(ctx, pgTunnelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	if tunnel.UserID != userID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	// Delete tunnel (this will also trigger cleanup in data plane)
	err = h.db.Queries.DeleteTunnel(ctx, sqlc.DeleteTunnelParams{
		ID:     pgTunnelID,
		UserID: pgUserID,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": "Failed to delete tunnel",
		})
		return
	}

	// TODO: Notify data plane to close tunnel connections
	// This should trigger tunnel manager to close agent connections

	c.JSON(http.StatusOK, gin.H{
		"status":    "terminated",
		"tunnel_id": tunnelID.String(),
		"message":   "Tunnel terminated successfully",
	})
}

// GetTunnelStats gets tunnel statistics - Control Plane API
func (h *TunnelHandler) GetTunnelStats(c *gin.Context) {
	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	tunnelIDStr := c.Param("tunnel_id")
	tunnelID, err := uuid.Parse(tunnelIDStr)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	// Parse query parameters (TODO: Use these for filtering)
	_ = c.DefaultQuery("period", "24h")
	_ = c.DefaultQuery("metrics", "requests,bandwidth,latency")

	ctx := c.Request.Context()

	// Convert UUIDs to uuid.UUID
	var pgTunnelID uuid.UUID
	pgTunnelID.Scan(tunnelID.String())

	// Verify tunnel ownership
	tunnel, err := h.db.Queries.GetTunnelByID(ctx, pgTunnelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	if tunnel.UserID != userID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	// Get tunnel analytics (simulated for now)
	// TODO: Implement real analytics collection and database queries

	// Get active connections count
	activeConnections, err := h.db.Queries.CountActiveConnections(ctx, pgTunnelID)
	if err != nil {
		activeConnections = 0 // Default to 0 if can't count
	}

	// Format analytics response (simulated data for now)
	var totalRequests, totalBytesIn, totalBytesOut int64 = 123, 1024 * 1024 * 5, 1024 * 1024 * 3 // 5MB in, 3MB out

	response := TunnelStatsResponse{
		TunnelID:          tunnelID.String(),
		ActiveConnections: activeConnections,
		TotalRequests:     totalRequests,
		TotalBytesIn:      totalBytesIn,
		TotalBytesOut:     totalBytesOut,
		Analytics:         []TunnelAnalyticsPoint{}, // Empty analytics for now
	}

	c.JSON(http.StatusOK, response)
}

// Helper functions

// formatTunnelListResponse formats a tunnel for list API response
func (h *TunnelHandler) formatTunnelListResponse(tunnel *sqlc.Tunnels) TunnelListResponse {
	response := TunnelListResponse{
		TunnelID:  tunnel.ID.String(),
		Protocol:  tunnel.Protocol,
		Status:    tunnel.Status,
		LocalPort: tunnel.TargetPort,
		CreatedAt: tunnel.CreatedAt.Time.Format(time.RFC3339),
		UpdatedAt: tunnel.UpdatedAt.Time.Format(time.RFC3339),
	}

	// Add subdomain and public URL for HTTP tunnels
	if tunnel.Subdomain.Valid {
		subdomain := tunnel.Subdomain.String
		response.Subdomain = &subdomain
		response.PublicURL = fmt.Sprintf("https://%s.%s", subdomain, h.config.Server.Domain)
	}

	// Add public port and URL for TCP tunnels
	if tunnel.PublicPort != nil {
		response.PublicPort = tunnel.PublicPort
		response.PublicURL = fmt.Sprintf("%s:%d", h.config.Tunnels.DomainHost, *tunnel.PublicPort)
	}

	return response
}

// isValidSubdomain validates custom subdomain requests
func isValidSubdomain(subdomain string) bool {
	if len(subdomain) < 3 || len(subdomain) > 20 {
		return false
	}

	// Only allow lowercase letters, numbers, and hyphens
	for _, char := range subdomain {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}

	// Can't start or end with hyphen
	if strings.HasPrefix(subdomain, "-") || strings.HasSuffix(subdomain, "-") {
		return false
	}

	return true
}

// isSubdomainAvailable checks if a subdomain is available
func (h *TunnelHandler) isSubdomainAvailable(ctx context.Context, subdomain string) bool {
	// Check if subdomain is already taken by an active tunnel
	_, err := h.db.Queries.GetTunnelBySubdomain(ctx, pgtype.Text{String: subdomain, Valid: true})
	return err != nil // If error (not found), then it's available
}

// generateRandomSubdomain generates a random subdomain
func (h *TunnelHandler) generateRandomSubdomain(ctx context.Context) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	length := h.config.Tunnels.SubdomainLength

	maxAttempts := 10
	for attempt := 0; attempt < maxAttempts; attempt++ {
		// Generate random subdomain
		b := make([]byte, length)
		for i := range b {
			b[i] = charset[rand.Intn(len(charset))]
		}
		subdomain := string(b)

		// Check if available
		if h.isSubdomainAvailable(ctx, subdomain) {
			return subdomain
		}
	}

	// Fallback: use timestamp-based subdomain
	return fmt.Sprintf("tunnel-%d", time.Now().Unix())
}

// findAvailablePort finds an available port for TCP tunnels
func (h *TunnelHandler) findAvailablePort(ctx context.Context) (int32, error) {
	// For now, return a random port in the tunnel range (30000-65535)
	// TODO: Implement actual port tracking in database
	for attempt := 0; attempt < 100; attempt++ {
		port := int32(30000 + rand.Intn(35535))

		// Check if port is available
		_, err := h.db.Queries.GetTunnelByPublicPort(ctx, pgtype.Int4{Int32: port, Valid: true})
		if err != nil { // Port not found = available
			return port, nil
		}
	}

	return 0, fmt.Errorf("no available ports found")
}
