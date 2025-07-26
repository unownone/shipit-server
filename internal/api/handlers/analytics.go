package handlers

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/unwonone/shipit-server/internal/api/middleware"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/logger"
)

// AnalyticsHandler handles analytics-related API endpoints
type AnalyticsHandler struct {
	db *database.Database
}

// NewAnalyticsHandler creates a new analytics handler
func NewAnalyticsHandler(db *database.Database) *AnalyticsHandler {
	return &AnalyticsHandler{
		db: db,
	}
}

// AnalyticsOverviewResponse represents user analytics overview
type AnalyticsOverviewResponse struct {
	TotalTunnels    int64  `json:"total_tunnels"`
	ActiveTunnels   int64  `json:"active_tunnels"`
	TotalRequests   int64  `json:"total_requests"`
	TotalBandwidth  string `json:"total_bandwidth"`  // Human readable (e.g., "2.3GB")
	TotalBandwidthBytes int64 `json:"total_bandwidth_bytes"`
	Period          string `json:"period"`
	GeneratedAt     string `json:"generated_at"`
}

// TunnelAnalyticsResponse represents specific tunnel analytics
type TunnelAnalyticsResponse struct {
	TunnelID   string                 `json:"tunnel_id"`
	Metrics    TunnelMetricsSummary   `json:"metrics"`
	TimeSeries []TunnelAnalyticsPoint `json:"time_series"`
	Period     string                 `json:"period"`
}

// TunnelMetricsSummary represents summarized tunnel metrics
type TunnelMetricsSummary struct {
	TotalRequests     int64   `json:"total_requests"`
	TotalBandwidth    string  `json:"total_bandwidth"`
	TotalBandwidthBytes int64 `json:"total_bandwidth_bytes"`
	AverageLatency    float32 `json:"average_latency_ms"`
	ErrorRate         float32 `json:"error_rate_percent"`
	UptimePercent     float32 `json:"uptime_percent"`
}

// TrafficAnalyticsResponse represents traffic analytics
type TrafficAnalyticsResponse struct {
	TopVisitors   []VisitorStat   `json:"top_visitors"`
	TopPaths      []PathStat      `json:"top_paths"`
	StatusCodes   map[string]int64 `json:"status_codes"`
	UserAgents    []UserAgentStat `json:"user_agents"`
	Countries     []CountryStat   `json:"countries"`
	Period        string          `json:"period"`
	GeneratedAt   string          `json:"generated_at"`
}

// VisitorStat represents visitor statistics
type VisitorStat struct {
	IPAddress string `json:"ip_address"`
	Requests  int64  `json:"requests"`
	Bandwidth int64  `json:"bandwidth_bytes"`
	Country   string `json:"country,omitempty"`
}

// PathStat represents path statistics
type PathStat struct {
	Path      string `json:"path"`
	Requests  int64  `json:"requests"`
	Bandwidth int64  `json:"bandwidth_bytes"`
}

// UserAgentStat represents user agent statistics
type UserAgentStat struct {
	UserAgent string `json:"user_agent"`
	Requests  int64  `json:"requests"`
	Percent   float32 `json:"percent"`
}

// CountryStat represents country statistics
type CountryStat struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Requests    int64  `json:"requests"`
	Percent     float32 `json:"percent"`
}

// GetOverview returns user's analytics overview - Control Plane API
// GET /api/analytics/overview?period=24h|7d|30d
func (h *AnalyticsHandler) GetOverview(c *gin.Context) {
	log := logger.Get()
	log.WithField("endpoint", "GetOverview").Debug("Analytics overview request")

	userID, exists := middleware.GetCurrentUserID(c)
	if !exists {
		log.WithField("endpoint", "GetOverview").Warn("User not authenticated for analytics overview")
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Parse period parameter
	period := c.DefaultQuery("period", "24h")
	if !isValidPeriod(period) {
		log.WithFields(map[string]interface{}{
			"endpoint": "GetOverview",
			"user_id":  userID.String(),
			"period":   period,
		}).Warn("Invalid period requested for analytics overview")
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid period. Must be '24h', '7d', or '30d'",
		})
		return
	}

	ctx := c.Request.Context()

	// Convert UUID to pgtype.UUID
	var pgUserID pgtype.UUID
	pgUserID.Scan(userID.String())

	// Get total tunnels count
	totalTunnels, err := h.db.Queries.CountTunnelsByUser(ctx, pgUserID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.String()).Error("Failed to count total tunnels")
		totalTunnels = 0
	}

	// Get active tunnels count
	activeTunnels, err := h.db.Queries.CountActiveTunnelsByUser(ctx, pgUserID)
	if err != nil {
		log.WithError(err).WithField("user_id", userID.String()).Error("Failed to count active tunnels")
		activeTunnels = 0
	}

	// Get aggregated analytics for the period
	// For now, we'll simulate this data since we haven't implemented the analytics collection yet
	var totalRequests, totalBandwidthBytes int64

	// In a real implementation, this would query analytics tables based on period
	// For now, return simulated data
	totalRequests = 1234                              // TODO: Implement real analytics query
	totalBandwidthBytes = 2470000000 // ~2.3GB in bytes

	response := AnalyticsOverviewResponse{
		TotalTunnels:        totalTunnels,
		ActiveTunnels:       activeTunnels,
		TotalRequests:       totalRequests,
		TotalBandwidth:      formatBandwidth(totalBandwidthBytes),
		TotalBandwidthBytes: totalBandwidthBytes,
		Period:              period,
		GeneratedAt:         time.Now().Format(time.RFC3339),
	}

	log.WithFields(map[string]interface{}{
		"user_id":        userID.String(),
		"period":         period,
		"total_tunnels":  totalTunnels,
		"active_tunnels": activeTunnels,
	}).Info("Analytics overview generated successfully")

	c.JSON(http.StatusOK, response)
}

// GetTunnelStats returns specific tunnel analytics - Control Plane API
// GET /api/analytics/tunnels/{tunnel_id}/stats?period=24h|7d|30d&metrics=requests,bandwidth,latency
func (h *AnalyticsHandler) GetTunnelStats(c *gin.Context) {
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
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid tunnel ID",
		})
		return
	}

	// Parse query parameters
	period := c.DefaultQuery("period", "24h")
	if !isValidPeriod(period) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid period. Must be '24h', '7d', or '30d'",
		})
		return
	}

	_ = c.DefaultQuery("metrics", "requests,bandwidth,latency") // TODO: Use metrics filtering

	ctx := c.Request.Context()

	// Convert UUIDs
	var pgTunnelID pgtype.UUID
	pgTunnelID.Scan(tunnelID.String())

	// Verify tunnel ownership
	tunnel, err := h.db.Queries.GetTunnelByID(ctx, pgTunnelID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	var tunnelUserID uuid.UUID
	tunnelUserID.Scan(tunnel.UserID.Bytes)
	if tunnelUserID != userID {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Tunnel not found",
		})
		return
	}

	// Get tunnel analytics (simulated for now)
	// TODO: Implement real analytics collection
	analytics := []TunnelAnalyticsPoint{}

	// Simulate analytics data for now
	var totalRequests, totalBandwidthBytes int64 = 456, 1024*1024*50 // 50MB
	var totalLatency, errorCount int64 = 125, 5

	// Calculate metrics summary
	var avgLatency, errorRate float32 = float32(totalLatency), 0
	if totalRequests > 0 {
		errorRate = (float32(errorCount) / float32(totalRequests)) * 100
	}

	summary := TunnelMetricsSummary{
		TotalRequests:       totalRequests,
		TotalBandwidth:      formatBandwidth(totalBandwidthBytes),
		TotalBandwidthBytes: totalBandwidthBytes,
		AverageLatency:      avgLatency,
		ErrorRate:           errorRate,
		UptimePercent:       99.9, // TODO: Calculate real uptime
	}

	response := TunnelAnalyticsResponse{
		TunnelID:   tunnelID.String(),
		Metrics:    summary,
		TimeSeries: analytics, // Using the simulated data
		Period:     period,
	}

	c.JSON(http.StatusOK, response)
}

// GetTrafficAnalytics returns traffic analytics - Control Plane API
// GET /api/analytics/traffic?period=24h|7d|30d
func (h *AnalyticsHandler) GetTrafficAnalytics(c *gin.Context) {
	_, exists := middleware.GetCurrentUserID(c)
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{
			"error": "User not authenticated",
		})
		return
	}

	// Parse period parameter
	period := c.DefaultQuery("period", "24h")
	if !isValidPeriod(period) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "Invalid period. Must be '24h', '7d', or '30d'",
		})
		return
	}

	// For now, return simulated traffic analytics
	// In a real implementation, this would query detailed analytics tables
	response := TrafficAnalyticsResponse{
		TopVisitors: []VisitorStat{
			{IPAddress: "192.168.1.1", Requests: 245, Bandwidth: 1024 * 1024, Country: "US"},
			{IPAddress: "10.0.0.1", Requests: 123, Bandwidth: 512 * 1024, Country: "CA"},
		},
		TopPaths: []PathStat{
			{Path: "/api/health", Requests: 150, Bandwidth: 30 * 1024},
			{Path: "/api/users", Requests: 89, Bandwidth: 45 * 1024},
		},
		StatusCodes: map[string]int64{
			"200": 890,
			"404": 45,
			"500": 12,
		},
		UserAgents: []UserAgentStat{
			{UserAgent: "Chrome/91.0", Requests: 456, Percent: 65.2},
			{UserAgent: "Firefox/89.0", Requests: 234, Percent: 33.4},
			{UserAgent: "Safari/14.1", Requests: 10, Percent: 1.4},
		},
		Countries: []CountryStat{
			{CountryCode: "US", CountryName: "United States", Requests: 567, Percent: 81.0},
			{CountryCode: "CA", CountryName: "Canada", Requests: 123, Percent: 17.6},
			{CountryCode: "GB", CountryName: "United Kingdom", Requests: 10, Percent: 1.4},
		},
		Period:      period,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	c.JSON(http.StatusOK, response)
}

// Helper functions

// isValidPeriod checks if the period parameter is valid
func isValidPeriod(period string) bool {
	return period == "24h" || period == "7d" || period == "30d"
}

// formatBandwidth converts bytes to human readable format
func formatBandwidth(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return strconv.FormatInt(bytes, 10) + " B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return strconv.FormatFloat(float64(bytes)/float64(div), 'f', 1, 64) + " " + []string{"KB", "MB", "GB", "TB"}[exp]
} 