// Package dataplane provides the main data plane server orchestration
package dataplane

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/agent"
	"github.com/unwonone/shipit-server/internal/analytics"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/logger"
	"github.com/unwonone/shipit-server/internal/proxy"
	"github.com/unwonone/shipit-server/internal/tunnel"
)

// Server represents the main data plane server
type Server struct {
	config *config.Config
	db     *database.Database

	// Core components
	tunnelManager      *tunnel.TunnelManager
	agentListener      *agent.AgentListener
	httpProxy          *proxy.HTTPProxy
	tcpProxy           *proxy.TCPProxy
	analyticsCollector *analytics.Collector

	// Server control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewServer creates a new data plane server
func NewServer(db *database.Database, config *config.Config) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	// Create tunnel manager
	tunnelManager := tunnel.NewTunnelManager(db)

	// Create analytics collector
	analyticsCollector := analytics.NewCollector(db)

	// Create agent listener
	agentListener := agent.NewAgentListener(tunnelManager, db, config)

	// Create proxy servers
	httpProxy := proxy.NewHTTPProxy(tunnelManager, config)
	tcpProxy := proxy.NewTCPProxy(tunnelManager, config)

	return &Server{
		config:             config,
		db:                 db,
		tunnelManager:      tunnelManager,
		agentListener:      agentListener,
		httpProxy:          httpProxy,
		tcpProxy:           tcpProxy,
		analyticsCollector: analyticsCollector,
		ctx:                ctx,
		cancel:             cancel,
	}
}

// Start starts all data plane components
func (s *Server) Start() error {
	log := logger.Get()
	log.Info("Starting ShipIt Data Plane Server")

	// Start analytics collector
	if err := s.analyticsCollector.Start(); err != nil {
		return fmt.Errorf("failed to start analytics collector: %w", err)
	}

	// Start agent listener (port 7223)
	if err := s.agentListener.Start(); err != nil {
		return fmt.Errorf("failed to start agent listener: %w", err)
	}

	// Start HTTP proxy (ports 80/443)
	if err := s.httpProxy.Start(); err != nil {
		return fmt.Errorf("failed to start HTTP proxy: %w", err)
	}

	// Start TCP proxy (dynamic ports)
	if err := s.tcpProxy.Start(); err != nil {
		return fmt.Errorf("failed to start TCP proxy: %w", err)
	}

	log.Info("ShipIt Data Plane Server started successfully")
	log.WithFields(map[string]interface{}{
		"agent_port":  s.config.Server.AgentPort,
		"http_port":   s.config.Server.HTTPPort,
		"https_port":  s.config.Server.HTTPSPort,
		"tls_enabled": s.config.TLS.CertFile != "",
		"analytics":   "enabled",
	}).Info("Data plane server configuration")

	return nil
}

// Stop gracefully stops all data plane components
func (s *Server) Stop() error {
	log := logger.Get()
	log.Info("Stopping ShipIt Data Plane Server")

	// Cancel context
	s.cancel()

	var errors []error

	// Stop TCP proxy
	if err := s.tcpProxy.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("TCP proxy stop error: %w", err))
	}

	// Stop HTTP proxy
	if err := s.httpProxy.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("HTTP proxy stop error: %w", err))
	}

	// Stop agent listener
	if err := s.agentListener.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("agent listener stop error: %w", err))
	}

	// Stop tunnel manager
	s.tunnelManager.Shutdown()

	// Stop analytics collector
	if err := s.analyticsCollector.Stop(); err != nil {
		errors = append(errors, fmt.Errorf("analytics collector stop error: %w", err))
	}

	// Wait for all components to stop
	s.wg.Wait()

	if len(errors) > 0 {
		log.WithField("error_count", len(errors)).Warn("Shutdown completed with errors")
		for _, err := range errors {
			log.WithError(err).Error("Shutdown error")
		}
		return errors[0] // Return first error
	}

	log.Info("ShipIt Data Plane Server stopped gracefully")
	return nil
}

// GetStats returns comprehensive statistics about all components
func (s *Server) GetStats() *DataPlaneStats {
	tunnelStats := s.tunnelManager.GetStats()
	agentStats := s.agentListener.GetStats()
	httpStats := s.httpProxy.GetStats()
	tcpStats := s.tcpProxy.GetStats()
	analyticsStats := s.analyticsCollector.GetCollectorStats()

	// Count total active tunnels and connections
	var totalTunnels, totalConnections int64
	for _, tunnelStat := range tunnelStats {
		totalTunnels++
		totalConnections += int64(tunnelStat.ConnectionCount)
	}

	return &DataPlaneStats{
		TunnelStats: DataPlaneTunnelStats{
			TotalTunnels:     totalTunnels,
			TotalConnections: totalConnections,
			TotalRequests:    httpStats.TotalRequests + tcpStats.TotalConnections,
			TotalBytesIn:     httpStats.TotalBytesIn + tcpStats.TotalBytesIn,
			TotalBytesOut:    httpStats.TotalBytesOut + tcpStats.TotalBytesOut,
			Tunnels:          tunnelStats,
		},
		AgentStats:     agentStats,
		HTTPStats:      httpStats,
		TCPStats:       tcpStats,
		AnalyticsStats: analyticsStats,
	}
}

// DataPlaneStats represents comprehensive data plane statistics
type DataPlaneStats struct {
	TunnelStats    DataPlaneTunnelStats     `json:"tunnel_stats"`
	AgentStats     agent.AgentListenerStats `json:"agent_stats"`
	HTTPStats      proxy.HTTPProxyStats     `json:"http_stats"`
	TCPStats       proxy.TCPProxyStats      `json:"tcp_stats"`
	AnalyticsStats analytics.CollectorStats `json:"analytics_stats"`
}

// DataPlaneTunnelStats represents aggregated tunnel statistics
type DataPlaneTunnelStats struct {
	TotalTunnels     int64                             `json:"total_tunnels"`
	TotalConnections int64                             `json:"total_connections"`
	TotalRequests    int64                             `json:"total_requests"`
	TotalBytesIn     int64                             `json:"total_bytes_in"`
	TotalBytesOut    int64                             `json:"total_bytes_out"`
	Tunnels          map[uuid.UUID]*tunnel.TunnelStats `json:"tunnels"`
}

// CreateTCPListener creates a TCP listener for a tunnel
func (s *Server) CreateTCPListener(tunnelID uuid.UUID, port int32) error {
	return s.tcpProxy.CreateListener(tunnelID, port)
}

// RemoveTCPListener removes a TCP listener
func (s *Server) RemoveTCPListener(port int32) error {
	return s.tcpProxy.RemoveListener(port)
}

// GetTunnelManager returns the tunnel manager (for integration)
func (s *Server) GetTunnelManager() *tunnel.TunnelManager {
	return s.tunnelManager
}

// GetAnalyticsCollector returns the analytics collector (for integration)
func (s *Server) GetAnalyticsCollector() *analytics.Collector {
	return s.analyticsCollector
}

// GetAgentListener returns the agent listener (for integration)
func (s *Server) GetAgentListener() *agent.AgentListener {
	return s.agentListener
}

// GetHTTPProxy returns the HTTP proxy (for integration)
func (s *Server) GetHTTPProxy() *proxy.HTTPProxy {
	return s.httpProxy
}

// GetTCPProxy returns the TCP proxy (for integration)
func (s *Server) GetTCPProxy() *proxy.TCPProxy {
	return s.tcpProxy
}
