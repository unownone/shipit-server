// Package proxy provides TCP proxy functionality for raw TCP tunnel forwarding
package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/logger"
	"github.com/unwonone/shipit-server/internal/tunnel"
)

// TCPProxy handles TCP traffic routing to tunnels
type TCPProxy struct {
	tunnelManager *tunnel.TunnelManager
	config        *config.Config
	
	// Active listeners for TCP tunnels
	listeners map[int32]*TCPListener
	mutex     sync.RWMutex
	
	// Server control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Statistics
	totalConnections int64
	activeConnections int32
	totalBytesIn     int64
	totalBytesOut    int64
	totalErrors      int64
}

// TCPListener represents a listener for a specific TCP tunnel
type TCPListener struct {
	Port      int32
	TunnelID  uuid.UUID
	Listener  net.Listener
	Proxy     *TCPProxy
	
	// Statistics
	connections int64
	bytesIn     int64
	bytesOut    int64
	
	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mutex  sync.RWMutex
}

// TCPConnection represents an active TCP connection being proxied
type TCPConnection struct {
	ID        string
	TunnelID  uuid.UUID
	ClientConn net.Conn
	StartTime time.Time
	BytesIn   int64
	BytesOut  int64
	
	// Connection control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewTCPProxy creates a new TCP proxy
func NewTCPProxy(tunnelManager *tunnel.TunnelManager, config *config.Config) *TCPProxy {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &TCPProxy{
		tunnelManager: tunnelManager,
		config:        config,
		listeners:     make(map[int32]*TCPListener),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the TCP proxy (listeners are created dynamically)
func (tp *TCPProxy) Start() error {
	logger.Get().Info("TCP proxy started")
	return nil
}

// Stop gracefully stops the TCP proxy and all listeners
func (tp *TCPProxy) Stop() error {
	logger.Get().Info("Stopping TCP proxy")
	
	// Cancel context
	tp.cancel()
	
	// Stop all listeners
	tp.mutex.Lock()
	for port, listener := range tp.listeners {
		logger.WithField("port", port).Debug("Stopping TCP listener")
		listener.Stop()
	}
	tp.listeners = make(map[int32]*TCPListener)
	tp.mutex.Unlock()
	
	// Wait for all goroutines to finish
	tp.wg.Wait()
	
	logger.Get().Info("TCP proxy stopped")
	return nil
}

// CreateListener creates a TCP listener for a specific tunnel
func (tp *TCPProxy) CreateListener(tunnelID uuid.UUID, port int32) error {
	tp.mutex.Lock()
	defer tp.mutex.Unlock()
	
	// Check if listener already exists
	if _, exists := tp.listeners[port]; exists {
		return fmt.Errorf("listener already exists on port %d", port)
	}
	
	// Create TCP listener
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener on port %d: %w", port, err)
	}
	
	// Create TCP listener wrapper
	ctx, cancel := context.WithCancel(tp.ctx)
	tcpListener := &TCPListener{
		Port:     port,
		TunnelID: tunnelID,
		Listener: listener,
		Proxy:    tp,
		ctx:      ctx,
		cancel:   cancel,
	}
	
	tp.listeners[port] = tcpListener
	
	// Start listener in goroutine
	tp.wg.Add(1)
	go func() {
		defer tp.wg.Done()
		tcpListener.Start()
	}()
	
	logger.WithFields(map[string]interface{}{
		"port":      port,
		"tunnel_id": tunnelID.String(),
	}).Info("TCP listener created")
	return nil
}

// RemoveListener removes a TCP listener for a specific port
func (tp *TCPProxy) RemoveListener(port int32) error {
	tp.mutex.Lock()
	defer tp.mutex.Unlock()
	
	listener, exists := tp.listeners[port]
	if !exists {
		return fmt.Errorf("no listener found on port %d", port)
	}
	
	// Stop listener
	listener.Stop()
	delete(tp.listeners, port)
	
	logger.WithField("port", port).Info("TCP listener removed")
	return nil
}

// GetListener returns the TCP listener for a specific port
func (tp *TCPProxy) GetListener(port int32) (*TCPListener, bool) {
	tp.mutex.RLock()
	defer tp.mutex.RUnlock()
	
	listener, exists := tp.listeners[port]
	return listener, exists
}

// GetStats returns statistics about the TCP proxy
func (tp *TCPProxy) GetStats() TCPProxyStats {
	tp.mutex.RLock()
	defer tp.mutex.RUnlock()
	
	stats := TCPProxyStats{
		TotalConnections:  tp.totalConnections,
		ActiveConnections: tp.activeConnections,
		TotalBytesIn:      tp.totalBytesIn,
		TotalBytesOut:     tp.totalBytesOut,
		TotalErrors:       tp.totalErrors,
		ActiveListeners:   int32(len(tp.listeners)),
		Listeners:         make([]TCPListenerStats, 0, len(tp.listeners)),
	}
	
	// Collect listener stats
	for _, listener := range tp.listeners {
		listener.mutex.RLock()
		listenerStats := TCPListenerStats{
			Port:        listener.Port,
			TunnelID:    listener.TunnelID,
			Connections: listener.connections,
			BytesIn:     listener.bytesIn,
			BytesOut:    listener.bytesOut,
		}
		listener.mutex.RUnlock()
		stats.Listeners = append(stats.Listeners, listenerStats)
	}
	
	return stats
}

// TCPProxyStats represents statistics for the TCP proxy
type TCPProxyStats struct {
	TotalConnections  int64
	ActiveConnections int32
	TotalBytesIn      int64
	TotalBytesOut     int64
	TotalErrors       int64
	ActiveListeners   int32
	Listeners         []TCPListenerStats
}

// TCPListenerStats represents statistics for a TCP listener
type TCPListenerStats struct {
	Port        int32
	TunnelID    uuid.UUID
	Connections int64
	BytesIn     int64
	BytesOut    int64
}

// TCPListener methods

// Start starts accepting connections on the TCP listener
func (tl *TCPListener) Start() {
	defer tl.Listener.Close()
	
	logger.WithField("port", tl.Port).Info("TCP listener started")
	
	for {
		select {
		case <-tl.ctx.Done():
			return
		default:
			// Set accept timeout to allow for graceful shutdown
			if tcpListener, ok := tl.Listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}
			
			conn, err := tl.Listener.Accept()
			if err != nil {
				// Check if it's a timeout or if we're shutting down
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if tl.ctx.Err() != nil {
					// Context cancelled, we're shutting down
					return
				}
				logger.WithField("port", tl.Port).Errorf("TCP listener port %d: error accepting connection: %v", tl.Port, err)
				continue
			}
			
			// Handle connection in goroutine
			tl.wg.Add(1)
			go func() {
				defer tl.wg.Done()
				tl.handleConnection(conn)
			}()
		}
	}
}

// Stop stops the TCP listener
func (tl *TCPListener) Stop() {
	tl.cancel()
	tl.Listener.Close()
	tl.wg.Wait()
	logger.WithField("port", tl.Port).Info("TCP listener stopped")
}

// handleConnection handles a new TCP connection
func (tl *TCPListener) handleConnection(clientConn net.Conn) {
	defer clientConn.Close()
	
	// Update statistics
	tl.mutex.Lock()
	tl.connections++
	tl.mutex.Unlock()
	
	tl.Proxy.mutex.Lock()
	tl.Proxy.totalConnections++
	tl.Proxy.activeConnections++
	connectionID := fmt.Sprintf("tcp_%d_%d", tl.Port, time.Now().UnixNano())
	tl.Proxy.mutex.Unlock()
	
	defer func() {
		tl.Proxy.mutex.Lock()
		tl.Proxy.activeConnections--
		tl.Proxy.mutex.Unlock()
	}()
	
	logger.WithFields(map[string]interface{}{
		"connection_id": connectionID,
		"remote_addr":   clientConn.RemoteAddr(),
		"port":          tl.Port,
	}).Info("TCP connection established")
	
	// Create TCP connection context
	ctx, cancel := context.WithCancel(tl.ctx)
	defer cancel()
	
	tcpConn := &TCPConnection{
		ID:         connectionID,
		TunnelID:   tl.TunnelID,
		ClientConn: clientConn,
		StartTime:  time.Now(),
		ctx:        ctx,
		cancel:     cancel,
	}
	
	// Find tunnel
	tunnelObj, err := tl.Proxy.tunnelManager.GetTunnelByPort(tl.Port)
	if err != nil {
		logger.WithFields(map[string]interface{}{
			"connection_id": connectionID,
			"port":          tl.Port,
			"error":         err,
		}).Errorf("TCP connection %s: tunnel not found for port %d", connectionID, tl.Port)
		return
	}
	
	// Check tunnel state
	if tunnelObj.State != tunnel.StateActive {
		logger.WithFields(map[string]interface{}{
			"connection_id": connectionID,
			"port":          tl.Port,
			"tunnel_state":  tunnelObj.State,
		}).Errorf("TCP connection %s: tunnel not active (state: %s)", connectionID, tunnelObj.State)
		return
	}
	
	// Start TCP proxy for this connection
	if err := tcpConn.startProxy(tunnelObj, tl); err != nil {
		logger.WithFields(map[string]interface{}{
			"connection_id": connectionID,
			"port":          tl.Port,
			"error":         err,
		}).Errorf("TCP connection %s: proxy failed", connectionID)
		return
	}
	
	duration := time.Since(tcpConn.StartTime)
	logger.WithFields(map[string]interface{}{
		"connection_id": connectionID,
		"duration":      duration,
		"bytes_in":      tcpConn.BytesIn,
		"bytes_out":     tcpConn.BytesOut,
	}).Info("TCP connection completed")
}

// TCPConnection methods

// startProxy starts proxying data between client and tunnel
func (tc *TCPConnection) startProxy(tunnelObj *tunnel.Tunnel, listener *TCPListener) error {
	// Create pipes for bidirectional communication
	clientReader, clientWriter := io.Pipe()
	tunnelReader, tunnelWriter := io.Pipe()
	
	// Start client -> tunnel forwarding
	tc.wg.Add(1)
	go func() {
		defer tc.wg.Done()
		defer clientWriter.Close()
		
		bytesRead, err := io.Copy(clientWriter, tc.ClientConn)
		if err != nil && tc.ctx.Err() == nil {
			logger.WithField("connection_id", tc.ID).Errorf("TCP connection %s: client->tunnel copy error: %v", err)
		}
		
		tc.BytesIn += bytesRead
		listener.mutex.Lock()
		listener.bytesIn += bytesRead
		listener.mutex.Unlock()
		
		listener.Proxy.mutex.Lock()
		listener.Proxy.totalBytesIn += bytesRead
		listener.Proxy.mutex.Unlock()
	}()
	
	// Start tunnel -> client forwarding
	tc.wg.Add(1)
	go func() {
		defer tc.wg.Done()
		defer tunnelWriter.Close()
		
		bytesWritten, err := io.Copy(tc.ClientConn, tunnelReader)
		if err != nil && tc.ctx.Err() == nil {
			logger.WithField("connection_id", tc.ID).Errorf("TCP connection %s: tunnel->client copy error: %v", err)
		}
		
		tc.BytesOut += bytesWritten
		listener.mutex.Lock()
		listener.bytesOut += bytesWritten
		listener.mutex.Unlock()
		
		listener.Proxy.mutex.Lock()
		listener.Proxy.totalBytesOut += bytesWritten
		listener.Proxy.mutex.Unlock()
	}()
	
	// Handle tunnel forwarding
	tc.wg.Add(1)
	go func() {
		defer tc.wg.Done()
		defer clientReader.Close()
		defer tunnelReader.Close()
		
		tc.handleTunnelForwarding(tunnelObj, clientReader, tunnelWriter)
	}()
	
	// Wait for connection to complete
	tc.wg.Wait()
	return nil
}

// handleTunnelForwarding handles the actual forwarding through the tunnel
func (tc *TCPConnection) handleTunnelForwarding(tunnelObj *tunnel.Tunnel, clientReader io.Reader, tunnelWriter io.Writer) {
	// TODO: Implement proper TCP tunnel forwarding
	// Current limitation: TCP requires streaming protocol, not HTTP-style request/response
	// For now, we'll do a simple passthrough to maintain the interface
	
	logger.WithField("connection_id", tc.ID).Info("TCP connection: forwarding through tunnel (simplified implementation)")
	
	// Create a buffer for reading data
	buffer := make([]byte, 32*1024) // 32KB buffer
	
	for {
		select {
		case <-tc.ctx.Done():
			return
		default:
			// Read data from client
			n, err := clientReader.Read(buffer)
			if err != nil {
				if err != io.EOF && tc.ctx.Err() == nil {
					logger.WithField("connection_id", tc.ID).Errorf("TCP connection %s: read error: %v", err)
				}
				return
			}
			
			if n > 0 {
				// TODO: Replace this with proper TCP tunnel protocol
				// The real implementation would:
				// 1. Get an available tunnel connection from the pool
				// 2. Send framed TCP data through the tunnel connection
				// 3. Handle bidirectional streaming properly
				// 4. Implement proper error handling and connection recovery
				
				// For now, write data directly to maintain the interface
				if _, err := tunnelWriter.Write(buffer[:n]); err != nil {
					if tc.ctx.Err() == nil {
						logger.WithField("connection_id", tc.ID).Errorf("TCP connection %s: write error: %v", err)
					}
					return
				}
			}
		}
	}
} 