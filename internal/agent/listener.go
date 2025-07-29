// Package agent provides the agent listener server for data plane connections
package agent

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/database"
	"github.com/unwonone/shipit-server/internal/logger"
	"github.com/unwonone/shipit-server/internal/tunnel"
)

// Listener handles incoming connections from client agents on the data plane
type Listener struct {
	listener      net.Listener
	tunnelManager *tunnel.Manager
	db            *database.Database
	config        *config.Config
	tlsConfig     *tls.Config

	// Connection management
	connections map[string]*Session
	mutex       sync.RWMutex

	// Server control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Statistics
	totalConnections  int64
	activeConnections int32
	totalDataBytes    int64
	messagesProcessed int64
}

// Session represents an active session with a client agent
type Session struct {
	ID            string
	TunnelID      uuid.UUID
	Conn          net.Conn
	UserID        uuid.UUID
	Protocol      string
	LocalPort     int32
	CreatedAt     time.Time
	LastHeartbeat time.Time
	IsActive      bool

	// Message channels
	incomingChan chan *Message
	outgoingChan chan *Message

	// Session control
	ctx    context.Context
	cancel context.CancelFunc
	mutex  sync.RWMutex
	wg     sync.WaitGroup
}

// NewListener creates a new agent listener
func NewListener(tunnelManager *tunnel.Manager, db *database.Database, config *config.Config) *Listener {
	ctx, cancel := context.WithCancel(context.Background())

	return &Listener{
		tunnelManager: tunnelManager,
		db:            db,
		config:        config,
		connections:   make(map[string]*Session),
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the agent listener server on the configured port
func (al *Listener) Start() error {
	// Configure TLS
	tlsConfig, err := al.setupTLS()
	if err != nil {
		return fmt.Errorf("failed to setup TLS: %w", err)
	}
	al.tlsConfig = tlsConfig

	// Create listener
	addr := fmt.Sprintf(":%d", al.config.Server.AgentPort)
	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start agent listener on %s: %w", addr, err)
	}

	al.listener = listener
	logger.WithField("port", al.config.Server.AgentPort).Info("Agent listener started")

	// Start accepting connections
	al.wg.Add(1)
	go func() {
		defer al.wg.Done()
		al.acceptConnections()
	}()

	return nil
}

// Stop gracefully stops the agent listener
func (al *Listener) Stop() error {
	logger.Get().Info("Stopping agent listener")

	// Cancel context to stop all goroutines
	al.cancel()

	// Close listener
	if al.listener != nil {
		if err := al.listener.Close(); err != nil {
			logger.Get().WithError(err).Error("Failed to close agent listener")
		}
	}

	// Close all active sessions
	al.mutex.Lock()
	for _, session := range al.connections {
		session.close()
	}
	al.connections = make(map[string]*Session)
	al.mutex.Unlock()

	// Wait for all goroutines to finish
	al.wg.Wait()

	logger.Get().Info("Agent listener stopped")
	return nil
}

// acceptConnections accepts incoming agent connections
func (al *Listener) acceptConnections() {
	for {
		select {
		case <-al.ctx.Done():
			return
		default:
			// Set accept timeout to allow for graceful shutdown
			if tcpListener, ok := al.listener.(*net.TCPListener); ok {
				if err := tcpListener.SetDeadline(time.Now().Add(1 * time.Second)); err != nil {
					logger.Get().WithError(err).Error("Failed to set TCP listener deadline")
				}
			}

			conn, err := al.listener.Accept()
			if err != nil {
				// Check if it's a timeout or if we're shutting down
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if al.ctx.Err() != nil {
					// Context cancelled, we're shutting down
					return
				}
				logger.WithError(err).Error("Error accepting connection")
				continue
			}

			// Handle connection in goroutine
			al.wg.Add(1)
			go func() {
				defer al.wg.Done()
				al.handleConnection(conn)
			}()
		}
	}
}

// handleConnection handles a new agent connection
func (al *Listener) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); err != nil {
			logger.Get().WithError(err).Error("Failed to close agent connection")
		}
	}()

	// Update statistics
	al.mutex.Lock()
	al.totalConnections++
	al.activeConnections++
	al.mutex.Unlock()

	defer func() {
		al.mutex.Lock()
		al.activeConnections--
		al.mutex.Unlock()
	}()

	logger.WithField("remote_addr", conn.RemoteAddr()).Info("New agent connection")

	// Set initial read timeout for tunnel registration
	if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
		logger.Get().WithError(err).Error("Failed to set read deadline")
	}

	// Read tunnel registration message
	msg, err := ReadMessage(conn)
	if err != nil {
		logger.WithError(err).Error("Failed to read registration message")
		al.sendErrorMessage(conn, uuid.Nil, "PROTOCOL_ERROR", "Failed to read registration message")
		return
	}

	if msg.Type != MessageTypeTunnelRegistration {
		logger.WithField("expected_type", MessageTypeTunnelRegistration).WithField("got_type", msg.Type).Error("Expected tunnel registration, got unexpected message type")
		al.sendErrorMessage(conn, msg.TunnelID, "INVALID_MESSAGE_TYPE", "Expected tunnel registration")
		return
	}

	// Parse registration payload
	var regPayload TunnelRegistrationPayload
	if err := json.Unmarshal(msg.Payload, &regPayload); err != nil {
		logger.WithError(err).Error("Failed to parse registration payload")
		al.sendErrorMessage(conn, msg.TunnelID, "INVALID_PAYLOAD", "Failed to parse registration payload")
		return
	}

	// Validate tunnel exists and user has access
	_, err = al.validateTunnelAccess(al.ctx, msg.TunnelID, &regPayload)
	if err != nil {
		logger.WithError(err).Error("Tunnel validation failed")
		al.sendErrorMessage(conn, msg.TunnelID, "TUNNEL_VALIDATION_FAILED", err.Error())
		return
	}

	// Register tunnel with tunnel manager
	managedTunnel, err := al.tunnelManager.RegisterTunnel(al.ctx, msg.TunnelID)
	if err != nil {
		logger.WithError(err).Error("Failed to register tunnel")
		al.sendErrorMessage(conn, msg.TunnelID, "TUNNEL_REGISTRATION_FAILED", err.Error())
		return
	}

	// Add connection to tunnel pool
	agentConn, err := al.tunnelManager.AddConnection(msg.TunnelID, conn)
	if err != nil {
		logger.WithError(err).Error("Failed to add connection to tunnel pool")
		al.sendErrorMessage(conn, msg.TunnelID, "CONNECTION_POOL_FULL", err.Error())
		return
	}

	// Create agent session
	session := al.createAgentSession(msg.TunnelID, conn, managedTunnel, agentConn, &regPayload)

	// Register session
	al.mutex.Lock()
	al.connections[session.ID] = session
	al.mutex.Unlock()

	// Send acknowledgment
	ackPayload := AcknowledgePayload{
		MessageType: MessageTypeTunnelRegistration,
		Success:     true,
		Message:     "Tunnel registered successfully",
	}
	if err := al.sendAcknowledgment(conn, msg.TunnelID, &ackPayload); err != nil {
		logger.WithError(err).Error("Failed to send acknowledgment")
		session.close()
		return
	}

	logger.WithField("session_id", session.ID).WithField("tunnel_id", msg.TunnelID).Info("Agent session established")

	// Start session handler
	session.start()

	// Wait for session to complete
	<-session.ctx.Done()

	// Cleanup
	al.mutex.Lock()
	delete(al.connections, session.ID)
	al.mutex.Unlock()

	// Remove connection from tunnel pool
	if err := al.tunnelManager.RemoveConnection(msg.TunnelID, agentConn.ID); err != nil {
		logger.Get().WithError(err).WithField("tunnel_id", msg.TunnelID).WithField("connection_id", agentConn.ID).Error("Failed to remove connection from tunnel pool")
	}

	logger.WithField("session_id", session.ID).Info("Agent session closed")
}

// validateTunnelAccess validates that the tunnel exists and the client has access
func (al *Listener) validateTunnelAccess(ctx context.Context, tunnelID uuid.UUID, regPayload *TunnelRegistrationPayload) (*tunnel.Tunnel, error) {
	// Get tunnel from database to verify it exists
	var pgTunnelID uuid.UUID
	if err := pgTunnelID.Scan(tunnelID.String()); err != nil {
		return nil, fmt.Errorf("failed to scan tunnel ID: %w", err)
	}

	dbTunnel, err := al.db.Queries.GetTunnelByID(ctx, pgTunnelID)
	if err != nil {
		return nil, fmt.Errorf("tunnel not found: %w", err)
	}

	// Verify tunnel is active
	if dbTunnel.Status != "active" {
		return nil, fmt.Errorf("tunnel is not active (status: %s)", dbTunnel.Status)
	}

	// Verify protocol matches
	if regPayload.Protocol != dbTunnel.Protocol {
		return nil, fmt.Errorf("protocol mismatch: expected %s, got %s", dbTunnel.Protocol, regPayload.Protocol)
	}

	// Verify target port matches
	if regPayload.LocalPort != dbTunnel.TargetPort {
		return nil, fmt.Errorf("target port mismatch: expected %d, got %d", dbTunnel.TargetPort, regPayload.LocalPort)
	}

	// Create tunnel object for validation
	tunnel := &tunnel.Tunnel{
		ID:         tunnelID,
		UserID:     dbTunnel.UserID,
		Protocol:   dbTunnel.Protocol,
		TargetHost: dbTunnel.TargetHost,
		TargetPort: dbTunnel.TargetPort,
	}

	return tunnel, nil
}

// createAgentSession creates a new agent session
func (al *Listener) createAgentSession(tunnelID uuid.UUID, conn net.Conn, managedTunnel *tunnel.Tunnel, agentConn *tunnel.AgentConnection, regPayload *TunnelRegistrationPayload) *Session {
	ctx, cancel := context.WithCancel(al.ctx)

	session := &Session{
		ID:            agentConn.ID,
		TunnelID:      tunnelID,
		Conn:          conn,
		UserID:        managedTunnel.UserID,
		Protocol:      regPayload.Protocol,
		LocalPort:     regPayload.LocalPort,
		CreatedAt:     time.Now(),
		LastHeartbeat: time.Now(),
		IsActive:      true,
		incomingChan:  make(chan *Message, 100),
		outgoingChan:  make(chan *Message, 100),
		ctx:           ctx,
		cancel:        cancel,
	}

	return session
}

// sendErrorMessage sends an error message to the client
func (al *Listener) sendErrorMessage(conn net.Conn, tunnelID uuid.UUID, code, message string) {
	errorPayload := ErrorPayload{
		Code:    code,
		Message: message,
	}

	payload, _ := json.Marshal(errorPayload)
	msg := &Message{
		Type:     MessageTypeError,
		TunnelID: tunnelID,
		Payload:  payload,
	}

	if err := WriteMessage(conn, msg); err != nil {
		logger.Get().WithError(err).Error("Failed to write error message")
	}
}

// sendAcknowledgment sends an acknowledgment message to the client
func (al *Listener) sendAcknowledgment(conn net.Conn, tunnelID uuid.UUID, ackPayload *AcknowledgePayload) error {
	payload, err := json.Marshal(ackPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal acknowledgment: %w", err)
	}

	msg := &Message{
		Type:     MessageTypeAcknowledge,
		TunnelID: tunnelID,
		Payload:  payload,
	}

	return WriteMessage(conn, msg)
}

// setupTLS configures TLS for the agent listener
func (al *Listener) setupTLS() (*tls.Config, error) {
	// For now, use a simple TLS configuration
	// In production, this should use proper certificates
	cert, err := tls.LoadX509KeyPair(al.config.TLS.CertFile, al.config.TLS.KeyFile)
	if err != nil {
		// Generate self-signed certificate for development
		cert, err = al.generateSelfSignedCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   al.config.Server.Domain,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// generateSelfSignedCert generates a self-signed certificate for development
func (al *Listener) generateSelfSignedCert() (tls.Certificate, error) {
	// TODO: Implement self-signed certificate generation
	// For now, return an error to indicate certificates are required
	return tls.Certificate{}, fmt.Errorf("TLS certificates required for agent listener")
}

// GetStats returns statistics about the agent listener
func (al *Listener) GetStats() ListenerStats {
	al.mutex.RLock()
	defer al.mutex.RUnlock()

	return ListenerStats{
		TotalConnections:  al.totalConnections,
		ActiveConnections: al.activeConnections,
		ActiveSessions:    int32(len(al.connections)),
		TotalDataBytes:    al.totalDataBytes,
		MessagesProcessed: al.messagesProcessed,
	}
}

// ListenerStats represents statistics for the agent listener
type ListenerStats struct {
	TotalConnections  int64
	ActiveConnections int32
	ActiveSessions    int32
	TotalDataBytes    int64
	MessagesProcessed int64
}

// AgentSession methods

// start starts the agent session message processing
func (as *Session) start() {
	// Start message reader
	as.wg.Add(1)
	go func() {
		defer as.wg.Done()
		as.messageReader()
	}()

	// Start message writer
	as.wg.Add(1)
	go func() {
		defer as.wg.Done()
		as.messageWriter()
	}()

	// Start message processor
	as.wg.Add(1)
	go func() {
		defer as.wg.Done()
		as.messageProcessor()
	}()

	// Start heartbeat monitor
	as.wg.Add(1)
	go func() {
		defer as.wg.Done()
		as.heartbeatMonitor()
	}()
}

// close closes the agent session
func (as *Session) close() {
	as.mutex.Lock()
	if !as.IsActive {
		as.mutex.Unlock()
		return
	}
	as.IsActive = false
	as.mutex.Unlock()

	as.cancel()
	if err := as.Conn.Close(); err != nil {
		logger.Get().WithError(err).WithField("session_id", as.ID).Error("Failed to close agent session connection")
	}
	close(as.incomingChan)
	close(as.outgoingChan)
}

// messageReader reads messages from the connection
func (as *Session) messageReader() {
	defer as.close()

	for {
		select {
		case <-as.ctx.Done():
			return
		default:
			// Set read timeout
			if err := as.Conn.SetReadDeadline(time.Now().Add(60 * time.Second)); err != nil {
				logger.Get().WithError(err).WithField("session_id", as.ID).Error("Failed to set read deadline")
			}

			msg, err := ReadMessage(as.Conn)
			if err != nil {
				if as.ctx.Err() == nil {
					logger.WithError(err).WithField("session_id", as.ID).Error("Failed to read message")
				}
				return
			}

			select {
			case as.incomingChan <- msg:
			case <-as.ctx.Done():
				return
			}
		}
	}
}

// messageWriter writes messages to the connection
func (as *Session) messageWriter() {
	defer as.close()

	for {
		select {
		case <-as.ctx.Done():
			return
		case msg := <-as.outgoingChan:
			if msg == nil {
				return
			}

			// Set write timeout
			if err := as.Conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
				logger.Get().WithError(err).WithField("session_id", as.ID).Error("Failed to set write deadline")
			}

			if err := WriteMessage(as.Conn, msg); err != nil {
				if as.ctx.Err() == nil {
					logger.WithError(err).WithField("session_id", as.ID).Error("Failed to write message")
				}
				return
			}
		}
	}
}

// messageProcessor processes incoming messages
func (as *Session) messageProcessor() {
	defer as.close()

	for {
		select {
		case <-as.ctx.Done():
			return
		case msg := <-as.incomingChan:
			if msg == nil {
				return
			}

			if err := as.processMessage(msg); err != nil {
				logger.WithError(err).WithField("session_id", as.ID).Error("Failed to process message")
				return
			}
		}
	}
}

// processMessage processes a single message
func (as *Session) processMessage(msg *Message) error {
	switch msg.Type {
	case MessageTypeHeartbeat:
		return as.handleHeartbeat(msg)
	case MessageTypeDataResponse:
		return as.handleDataResponse(msg)
	case MessageTypeConnectionClose:
		return as.handleConnectionClose(msg)
	default:
		logger.WithField("session_id", as.ID).WithField("message_type", msg.Type).Warn("Unexpected message type")
		return nil
	}
}

// handleHeartbeat handles heartbeat messages
func (as *Session) handleHeartbeat(msg *Message) error {
	as.mutex.Lock()
	as.LastHeartbeat = time.Now()
	as.mutex.Unlock()

	// Parse heartbeat payload
	var heartbeat HeartbeatPayload
	if err := json.Unmarshal(msg.Payload, &heartbeat); err != nil {
		return fmt.Errorf("failed to parse heartbeat: %w", err)
	}

	// Send heartbeat response
	response := HeartbeatPayload{
		Timestamp: time.Now().Unix(),
	}

	payload, _ := json.Marshal(response)
	responseMsg := &Message{
		Type:     MessageTypeHeartbeat,
		TunnelID: msg.TunnelID,
		Payload:  payload,
	}

	select {
	case as.outgoingChan <- responseMsg:
	case <-as.ctx.Done():
		return as.ctx.Err()
	}

	return nil
}

// handleDataResponse handles data response messages
func (as *Session) handleDataResponse(msg *Message) error {
	// TODO: Forward response back to the original requester
	// This will be implemented when we have the HTTP proxy
	logger.WithField("session_id", as.ID).WithField("payload_size", len(msg.Payload)).Info("Received data response")
	return nil
}

// handleConnectionClose handles connection close messages
func (as *Session) handleConnectionClose(_ *Message) error {
	logger.WithField("session_id", as.ID).Info("Received connection close request")
	// Close the session gracefully
	as.close()
	return nil
}

// heartbeatMonitor monitors heartbeat timeouts
func (as *Session) heartbeatMonitor() {
	ticker := time.NewTicker(60 * time.Second) // Check every minute
	defer ticker.Stop()

	for {
		select {
		case <-as.ctx.Done():
			return
		case <-ticker.C:
			as.mutex.RLock()
			lastHeartbeat := as.LastHeartbeat
			as.mutex.RUnlock()

			// Check if heartbeat is overdue (2 minutes without heartbeat)
			if time.Since(lastHeartbeat) > 2*time.Minute {
				logger.WithField("session_id", as.ID).Warn("Heartbeat timeout, closing session")
				as.close()
				return
			}
		}
	}
}
