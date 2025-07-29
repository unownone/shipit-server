// Package tunnel provides core tunnel management functionality
// This handles tunnel state, connection pools, and routing logic
package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/database"
)

// TunnelState represents the current state of a tunnel
type TunnelState string

const (
	StateConnecting TunnelState = "connecting" // Agent is connecting
	StateActive     TunnelState = "active"     // Tunnel is active and ready
	StateIdle       TunnelState = "idle"       // Tunnel exists but no connections
	StateTerminated TunnelState = "terminated" // Tunnel has been terminated
)

// ConnectionPool manages a pool of connections for a tunnel
type ConnectionPool struct {
	TunnelID    uuid.UUID
	Connections []*AgentConnection
	mutex       sync.RWMutex
	roundRobin  int // For load balancing
}

// AgentConnection represents a connection from a client agent
type AgentConnection struct {
	ID          string
	TunnelID    uuid.UUID
	Conn        net.Conn
	LastUsed    time.Time
	IsHealthy   bool
	RequestChan chan *ForwardRequest
	mutex       sync.RWMutex
}

// ForwardRequest represents a request to forward data through a tunnel
type ForwardRequest struct {
	ConnectionID string
	RequestID    string
	Data         []byte
	Headers      map[string]string
	Method       string
	Path         string
	ResponseChan chan *ForwardResponse
}

// ForwardResponse represents a response from the agent
type ForwardResponse struct {
	Data       []byte
	StatusCode int
	Headers    map[string]string
	Error      error
}

// Tunnel represents an active tunnel with its connection pool
type Tunnel struct {
	ID            uuid.UUID
	UserID        uuid.UUID
	Protocol      string
	Subdomain     string
	PublicPort    int32
	TargetHost    string
	TargetPort    int32
	State         TunnelState
	Pool          *ConnectionPool
	CreatedAt     time.Time
	LastActivity  time.Time
	
	// Statistics
	TotalRequests   int64
	TotalBytesIn    int64
	TotalBytesOut   int64
	ActiveRequests  int32
	
	mutex sync.RWMutex
}

// TunnelManager manages all active tunnels and their connection pools
type TunnelManager struct {
	tunnels  map[uuid.UUID]*Tunnel
	subdomains map[string]uuid.UUID // subdomain -> tunnel_id mapping
	ports    map[int32]uuid.UUID    // port -> tunnel_id mapping
	db       *database.Database
	mutex    sync.RWMutex
	
	// Configuration
	maxConnectionsPerTunnel int
	connectionTimeout       time.Duration
	heartbeatInterval       time.Duration
	cleanupInterval         time.Duration
	
	// Background workers
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(db *database.Database) *TunnelManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	tm := &TunnelManager{
		tunnels:    make(map[uuid.UUID]*Tunnel),
		subdomains: make(map[string]uuid.UUID),
		ports:      make(map[int32]uuid.UUID),
		db:         db,
		ctx:        ctx,
		cancel:     cancel,
		
		// Default configuration
		maxConnectionsPerTunnel: 10,
		connectionTimeout:       30 * time.Second,
		heartbeatInterval:       30 * time.Second,
		cleanupInterval:         5 * time.Minute,
	}
	
	// Start background workers
	tm.startBackgroundWorkers()
	
	return tm
}

// RegisterTunnel registers a new tunnel from the database
func (tm *TunnelManager) RegisterTunnel(ctx context.Context, tunnelID uuid.UUID) (*Tunnel, error) {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	// Check if tunnel already exists
	if existing, exists := tm.tunnels[tunnelID]; exists {
		return existing, nil
	}
	
	// Get tunnel from database
	var pgTunnelID uuid.UUID
	pgTunnelID.Scan(tunnelID.String())
	
	dbTunnel, err := tm.db.Queries.GetTunnelByID(ctx, pgTunnelID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tunnel from database: %w", err)
	}
	
	// Create tunnel
	tunnel := &Tunnel{
		ID:         tunnelID,
		UserID:     dbTunnel.UserID,
		Protocol:   dbTunnel.Protocol,
		TargetHost: dbTunnel.TargetHost,
		TargetPort: dbTunnel.TargetPort,
		State:      StateIdle,
		CreatedAt:  dbTunnel.CreatedAt.Time,
		LastActivity: time.Now(),
		Pool: &ConnectionPool{
			TunnelID:    tunnelID,
			Connections: make([]*AgentConnection, 0, tm.maxConnectionsPerTunnel),
		},
	}
	
	// Set protocol-specific fields
	if dbTunnel.Subdomain.Valid {
		tunnel.Subdomain = dbTunnel.Subdomain.String
		tm.subdomains[tunnel.Subdomain] = tunnelID
	}
	if dbTunnel.PublicPort != nil {
		tunnel.PublicPort = *dbTunnel.PublicPort
		tm.ports[tunnel.PublicPort] = tunnelID
	}
	
	tm.tunnels[tunnelID] = tunnel
	return tunnel, nil
}

// AddConnection adds a new agent connection to a tunnel
func (tm *TunnelManager) AddConnection(tunnelID uuid.UUID, conn net.Conn) (*AgentConnection, error) {
	tm.mutex.RLock()
	tunnel, exists := tm.tunnels[tunnelID]
	tm.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	
	tunnel.Pool.mutex.Lock()
	defer tunnel.Pool.mutex.Unlock()
	
	// Check connection limit
	if len(tunnel.Pool.Connections) >= tm.maxConnectionsPerTunnel {
		return nil, fmt.Errorf("connection pool full for tunnel %s", tunnelID)
	}
	
	// Create agent connection
	agentConn := &AgentConnection{
		ID:          fmt.Sprintf("%s-%d", tunnelID.String()[:8], len(tunnel.Pool.Connections)),
		TunnelID:    tunnelID,
		Conn:        conn,
		LastUsed:    time.Now(),
		IsHealthy:   true,
		RequestChan: make(chan *ForwardRequest, 100), // Buffered channel
	}
	
	tunnel.Pool.Connections = append(tunnel.Pool.Connections, agentConn)
	
	// Update tunnel state
	tunnel.mutex.Lock()
	if tunnel.State == StateIdle {
		tunnel.State = StateActive
	}
	tunnel.LastActivity = time.Now()
	tunnel.mutex.Unlock()
	
	return agentConn, nil
}

// RemoveConnection removes an agent connection from a tunnel
func (tm *TunnelManager) RemoveConnection(tunnelID uuid.UUID, connectionID string) error {
	tm.mutex.RLock()
	tunnel, exists := tm.tunnels[tunnelID]
	tm.mutex.RUnlock()
	
	if !exists {
		return fmt.Errorf("tunnel %s not found", tunnelID)
	}
	
	tunnel.Pool.mutex.Lock()
	defer tunnel.Pool.mutex.Unlock()
	
	// Find and remove connection
	for i, conn := range tunnel.Pool.Connections {
		if conn.ID == connectionID {
			// Close the connection
			conn.Conn.Close()
			close(conn.RequestChan)
			
			// Remove from slice
			tunnel.Pool.Connections = append(
				tunnel.Pool.Connections[:i],
				tunnel.Pool.Connections[i+1:]...,
			)
			
			// Update tunnel state if no connections remain
			tunnel.mutex.Lock()
			if len(tunnel.Pool.Connections) == 0 {
				tunnel.State = StateIdle
			}
			tunnel.mutex.Unlock()
			
			return nil
		}
	}
	
	return fmt.Errorf("connection %s not found in tunnel %s", connectionID, tunnelID)
}

// GetTunnelBySubdomain finds a tunnel by subdomain
func (tm *TunnelManager) GetTunnelBySubdomain(subdomain string) (*Tunnel, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	tunnelID, exists := tm.subdomains[subdomain]
	if !exists {
		return nil, fmt.Errorf("no tunnel found for subdomain %s", subdomain)
	}
	
	tunnel, exists := tm.tunnels[tunnelID]
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	
	return tunnel, nil
}

// GetTunnelByPort finds a tunnel by public port
func (tm *TunnelManager) GetTunnelByPort(port int32) (*Tunnel, error) {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	tunnelID, exists := tm.ports[port]
	if !exists {
		return nil, fmt.Errorf("no tunnel found for port %d", port)
	}
	
	tunnel, exists := tm.tunnels[tunnelID]
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	
	return tunnel, nil
}

// ForwardRequest forwards a request through the tunnel using round-robin load balancing
func (tm *TunnelManager) ForwardRequest(tunnelID uuid.UUID, req *ForwardRequest) (*ForwardResponse, error) {
	tm.mutex.RLock()
	tunnel, exists := tm.tunnels[tunnelID]
	tm.mutex.RUnlock()
	
	if !exists {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	
	if tunnel.State != StateActive {
		return nil, fmt.Errorf("tunnel %s is not active (state: %s)", tunnelID, tunnel.State)
	}
	
	// Get next available connection using round-robin
	conn, err := tunnel.Pool.getNextConnection()
	if err != nil {
		return nil, fmt.Errorf("no available connections: %w", err)
	}
	
	// Update statistics
	tunnel.mutex.Lock()
	tunnel.TotalRequests++
	tunnel.ActiveRequests++
	tunnel.LastActivity = time.Now()
	tunnel.mutex.Unlock()
	
	// Forward request
	select {
	case conn.RequestChan <- req:
		// Wait for response with timeout
		ctx, cancel := context.WithTimeout(context.Background(), tm.connectionTimeout)
		defer cancel()
		
		select {
		case resp := <-req.ResponseChan:
			tunnel.mutex.Lock()
			tunnel.ActiveRequests--
			if resp.Error == nil {
				tunnel.TotalBytesIn += int64(len(req.Data))
				tunnel.TotalBytesOut += int64(len(resp.Data))
			}
			tunnel.mutex.Unlock()
			return resp, nil
		case <-ctx.Done():
			tunnel.mutex.Lock()
			tunnel.ActiveRequests--
			tunnel.mutex.Unlock()
			return nil, fmt.Errorf("request timeout")
		}
	default:
		tunnel.mutex.Lock()
		tunnel.ActiveRequests--
		tunnel.mutex.Unlock()
		return nil, fmt.Errorf("connection request channel full")
	}
}

// TerminateTunnel terminates a tunnel and closes all connections
func (tm *TunnelManager) TerminateTunnel(tunnelID uuid.UUID) error {
	tm.mutex.Lock()
	defer tm.mutex.Unlock()
	
	tunnel, exists := tm.tunnels[tunnelID]
	if !exists {
		return fmt.Errorf("tunnel %s not found", tunnelID)
	}
	
	// Close all connections
	tunnel.Pool.mutex.Lock()
	for _, conn := range tunnel.Pool.Connections {
		conn.Conn.Close()
		close(conn.RequestChan)
	}
	tunnel.Pool.Connections = nil
	tunnel.Pool.mutex.Unlock()
	
	// Update state
	tunnel.mutex.Lock()
	tunnel.State = StateTerminated
	tunnel.mutex.Unlock()
	
	// Remove from maps
	delete(tm.tunnels, tunnelID)
	if tunnel.Subdomain != "" {
		delete(tm.subdomains, tunnel.Subdomain)
	}
	if tunnel.PublicPort > 0 {
		delete(tm.ports, tunnel.PublicPort)
	}
	
	return nil
}

// GetStats returns statistics for all tunnels
func (tm *TunnelManager) GetStats() map[uuid.UUID]*TunnelStats {
	tm.mutex.RLock()
	defer tm.mutex.RUnlock()
	
	stats := make(map[uuid.UUID]*TunnelStats)
	for id, tunnel := range tm.tunnels {
		tunnel.mutex.RLock()
		tunnel.Pool.mutex.RLock()
		
		stats[id] = &TunnelStats{
			TunnelID:        id,
			State:           tunnel.State,
			ConnectionCount: len(tunnel.Pool.Connections),
			TotalRequests:   tunnel.TotalRequests,
			TotalBytesIn:    tunnel.TotalBytesIn,
			TotalBytesOut:   tunnel.TotalBytesOut,
			ActiveRequests:  tunnel.ActiveRequests,
			LastActivity:    tunnel.LastActivity,
		}
		
		tunnel.Pool.mutex.RUnlock()
		tunnel.mutex.RUnlock()
	}
	
	return stats
}

// TunnelStats represents tunnel statistics
type TunnelStats struct {
	TunnelID        uuid.UUID
	State           TunnelState
	ConnectionCount int
	TotalRequests   int64
	TotalBytesIn    int64
	TotalBytesOut   int64
	ActiveRequests  int32
	LastActivity    time.Time
}

// ConnectionPool methods

// getNextConnection returns the next available connection using round-robin
func (cp *ConnectionPool) getNextConnection() (*AgentConnection, error) {
	cp.mutex.Lock()
	defer cp.mutex.Unlock()
	
	if len(cp.Connections) == 0 {
		return nil, fmt.Errorf("no connections available")
	}
	
	// Find next healthy connection
	startIndex := cp.roundRobin
	for i := 0; i < len(cp.Connections); i++ {
		index := (startIndex + i) % len(cp.Connections)
		conn := cp.Connections[index]
		
		if conn.IsHealthy {
			cp.roundRobin = (index + 1) % len(cp.Connections)
			conn.LastUsed = time.Now()
			return conn, nil
		}
	}
	
	return nil, fmt.Errorf("no healthy connections available")
}

// Background workers

// startBackgroundWorkers starts the background maintenance workers
func (tm *TunnelManager) startBackgroundWorkers() {
	// Cleanup worker
	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		ticker := time.NewTicker(tm.cleanupInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-tm.ctx.Done():
				return
			case <-ticker.C:
				tm.cleanupStaleConnections()
			}
		}
	}()
	
	// Heartbeat worker
	tm.wg.Add(1)
	go func() {
		defer tm.wg.Done()
		ticker := time.NewTicker(tm.heartbeatInterval)
		defer ticker.Stop()
		
		for {
			select {
			case <-tm.ctx.Done():
				return
			case <-ticker.C:
				tm.sendHeartbeats()
			}
		}
	}()
}

// cleanupStaleConnections removes stale connections and tunnels
func (tm *TunnelManager) cleanupStaleConnections() {
	tm.mutex.RLock()
	tunnelsToCheck := make([]*Tunnel, 0, len(tm.tunnels))
	for _, tunnel := range tm.tunnels {
		tunnelsToCheck = append(tunnelsToCheck, tunnel)
	}
	tm.mutex.RUnlock()
	
	for _, tunnel := range tunnelsToCheck {
		tunnel.Pool.mutex.Lock()
		
		// Check for stale connections
		staleConnections := make([]string, 0)
		for _, conn := range tunnel.Pool.Connections {
			if time.Since(conn.LastUsed) > tm.connectionTimeout*2 {
				staleConnections = append(staleConnections, conn.ID)
			}
		}
		
		tunnel.Pool.mutex.Unlock()
		
		// Remove stale connections
		for _, connID := range staleConnections {
			tm.RemoveConnection(tunnel.ID, connID)
		}
	}
}

// sendHeartbeats sends heartbeat messages to all connections
func (tm *TunnelManager) sendHeartbeats() {
	// TODO: Implement heartbeat sending to agent connections
	// This will be implemented when we have the agent listener
}

// Shutdown gracefully shuts down the tunnel manager
func (tm *TunnelManager) Shutdown() {
	tm.cancel()
	tm.wg.Wait()
	
	// Close all tunnels
	tm.mutex.Lock()
	for tunnelID := range tm.tunnels {
		tm.TerminateTunnel(tunnelID)
	}
	tm.mutex.Unlock()
} 