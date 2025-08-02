// Package analytics provides real-time metrics collection and storage
package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/unownone/shipit-server/internal/database"
	"github.com/unownone/shipit-server/internal/database/sqlc"
	"github.com/unownone/shipit-server/internal/logger"
)

// Collector handles real-time analytics collection and storage
type Collector struct {
	db *database.Database

	// In-memory metrics before batch insert
	metricsBatch map[uuid.UUID]*TunnelMetrics
	eventQueue   chan *Event

	// Configuration
	batchSize       int
	batchInterval   time.Duration
	queueSize       int
	retentionPeriod time.Duration

	// Background processing
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	mutex  sync.RWMutex

	// Statistics
	totalEvents     int64
	eventsProcessed int64
	batchesSaved    int64
	errors          int64
}

// Event represents a single analytics event
type Event struct {
	TunnelID     uuid.UUID
	EventType    EventType
	Timestamp    time.Time
	RequestID    string
	ConnectionID string
	Method       string
	Path         string
	StatusCode   int
	BytesIn      int64
	BytesOut     int64
	ResponseTime time.Duration
	ClientIP     string
	UserAgent    string
	ErrorMessage string
	Metadata     map[string]interface{}
}

// TunnelMetrics holds aggregated metrics for a tunnel
type TunnelMetrics struct {
	TunnelID          uuid.UUID
	RequestsCount     int64
	BytesIn           int64
	BytesOut          int64
	ErrorCount        int64
	TotalResponseTime time.Duration
	MinResponseTime   time.Duration
	MaxResponseTime   time.Duration
	LastActivity      time.Time
	ActiveConnections int32

	// Detailed breakdowns
	StatusCodes map[int]int64
	Methods     map[string]int64
	Paths       map[string]int64
	IPs         map[string]int64
	UserAgents  map[string]int64

	mutex sync.RWMutex
}

// EventType represents different types of analytics events
type EventType string

// EventType constants
const (
	EventTypeRequest    EventType = "request"
	EventTypeResponse   EventType = "response"
	EventTypeConnection EventType = "connection"
	EventTypeError      EventType = "error"
	EventTypeHeartbeat  EventType = "heartbeat"
)

// NewCollector creates a new analytics collector
func NewCollector(db *database.Database) *Collector {
	ctx, cancel := context.WithCancel(context.Background())

	collector := &Collector{
		db:           db,
		metricsBatch: make(map[uuid.UUID]*TunnelMetrics),
		eventQueue:   make(chan *Event, 10000), // 10k event buffer

		// Default configuration
		batchSize:       100,
		batchInterval:   30 * time.Second,
		queueSize:       10000,
		retentionPeriod: 30 * 24 * time.Hour, // 30 days

		ctx:    ctx,
		cancel: cancel,
	}

	return collector
}

// Start starts the analytics collector
func (c *Collector) Start() error {
	logger.Get().Info("Starting analytics collector")

	// Start event processor
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processEvents()
	}()

	// Start batch processor
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		c.processBatches()
	}()

	// Start cleanup worker
	c.wg.Add(1)

	logger.Get().Info("Analytics collector started")
	return nil
}

// Stop gracefully stops the analytics collector
func (c *Collector) Stop() error {
	logger.Get().Info("Stopping analytics collector")

	// Cancel context
	c.cancel()

	// Close event queue
	close(c.eventQueue)

	// Wait for all workers to finish
	c.wg.Wait()

	// Process any remaining metrics
	c.processFinalBatch()

	logger.Get().Info("Analytics collector stopped")
	return nil
}

// RecordEvent records an analytics event
func (c *Collector) RecordEvent(event *Event) {
	if event == nil {
		return
	}

	// Set timestamp if not provided
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	// Try to queue event
	select {
	case c.eventQueue <- event:
		c.mutex.Lock()
		c.totalEvents++
		c.mutex.Unlock()
	default:
		// Queue is full, drop event and log warning
		c.mutex.Lock()
		c.errors++
		c.mutex.Unlock()
		logger.WithField("tunnel_id", event.TunnelID.String()).Warn("Analytics event queue full, dropping event")
	}
}

// RecordHTTPRequest records an HTTP request event
func (c *Collector) RecordHTTPRequest(tunnelID uuid.UUID, requestID, connectionID, method, path string, bytesIn int64, clientIP, userAgent string) {
	event := &Event{
		TunnelID:     tunnelID,
		EventType:    EventTypeRequest,
		RequestID:    requestID,
		ConnectionID: connectionID,
		Method:       method,
		Path:         path,
		BytesIn:      bytesIn,
		ClientIP:     clientIP,
		UserAgent:    userAgent,
	}
	c.RecordEvent(event)
}

// RecordHTTPResponse records an HTTP response event
func (c *Collector) RecordHTTPResponse(tunnelID uuid.UUID, requestID string, statusCode int, bytesOut int64, responseTime time.Duration) {
	event := &Event{
		TunnelID:     tunnelID,
		EventType:    EventTypeResponse,
		RequestID:    requestID,
		StatusCode:   statusCode,
		BytesOut:     bytesOut,
		ResponseTime: responseTime,
	}
	c.RecordEvent(event)
}

// RecordTCPConnection records a TCP connection event
func (c *Collector) RecordTCPConnection(tunnelID uuid.UUID, connectionID string, bytesIn, bytesOut int64, duration time.Duration, clientIP string) {
	event := &Event{
		TunnelID:     tunnelID,
		EventType:    EventTypeConnection,
		ConnectionID: connectionID,
		BytesIn:      bytesIn,
		BytesOut:     bytesOut,
		ResponseTime: duration,
		ClientIP:     clientIP,
		Method:       "TCP",
	}
	c.RecordEvent(event)
}

// RecordError records an error event
func (c *Collector) RecordError(tunnelID uuid.UUID, requestID, errorMessage string, metadata map[string]interface{}) {
	event := &Event{
		TunnelID:     tunnelID,
		EventType:    EventTypeError,
		RequestID:    requestID,
		ErrorMessage: errorMessage,
		Metadata:     metadata,
	}
	c.RecordEvent(event)
}

// GetTunnelStats returns current statistics for a tunnel
func (c *Collector) GetTunnelStats(tunnelID uuid.UUID) *TunnelMetrics {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	metrics, exists := c.metricsBatch[tunnelID]
	if !exists {
		return &TunnelMetrics{
			TunnelID:    tunnelID,
			StatusCodes: make(map[int]int64),
			Methods:     make(map[string]int64),
			Paths:       make(map[string]int64),
			IPs:         make(map[string]int64),
			UserAgents:  make(map[string]int64),
		}
	}

	// Return a copy to avoid race conditions
	metrics.mutex.RLock()
	defer metrics.mutex.RUnlock()

	return &TunnelMetrics{
		TunnelID:          metrics.TunnelID,
		RequestsCount:     metrics.RequestsCount,
		BytesIn:           metrics.BytesIn,
		BytesOut:          metrics.BytesOut,
		ErrorCount:        metrics.ErrorCount,
		TotalResponseTime: metrics.TotalResponseTime,
		MinResponseTime:   metrics.MinResponseTime,
		MaxResponseTime:   metrics.MaxResponseTime,
		LastActivity:      metrics.LastActivity,
		ActiveConnections: metrics.ActiveConnections,
		StatusCodes:       copyMap(metrics.StatusCodes),
		Methods:           copyStringMap(metrics.Methods),
		Paths:             copyStringMap(metrics.Paths),
		IPs:               copyStringMap(metrics.IPs),
		UserAgents:        copyStringMap(metrics.UserAgents),
	}
}

// GetCollectorStats returns collector statistics
func (c *Collector) GetCollectorStats() CollectorStats {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	return CollectorStats{
		TotalEvents:     c.totalEvents,
		EventsProcessed: c.eventsProcessed,
		BatchesSaved:    c.batchesSaved,
		Errors:          c.errors,
		QueueSize:       int64(len(c.eventQueue)),
		QueueCapacity:   int64(cap(c.eventQueue)),
		ActiveTunnels:   int64(len(c.metricsBatch)),
	}
}

// CollectorStats represents collector statistics
type CollectorStats struct {
	TotalEvents     int64
	EventsProcessed int64
	BatchesSaved    int64
	Errors          int64
	QueueSize       int64
	QueueCapacity   int64
	ActiveTunnels   int64
}

// Background workers

// processEvents processes events from the queue
func (c *Collector) processEvents() {
	for {
		select {
		case <-c.ctx.Done():
			return
		case event, ok := <-c.eventQueue:
			if !ok {
				return // Channel closed
			}

			c.processEvent(event)

			c.mutex.Lock()
			c.eventsProcessed++
			c.mutex.Unlock()
		}
	}
}

// processEvent processes a single event
func (c *Collector) processEvent(event *Event) {
	c.mutex.Lock()
	metrics, exists := c.metricsBatch[event.TunnelID]
	if !exists {
		metrics = &TunnelMetrics{
			TunnelID:    event.TunnelID,
			StatusCodes: make(map[int]int64),
			Methods:     make(map[string]int64),
			Paths:       make(map[string]int64),
			IPs:         make(map[string]int64),
			UserAgents:  make(map[string]int64),
		}
		c.metricsBatch[event.TunnelID] = metrics
	}
	c.mutex.Unlock()

	// Update metrics
	metrics.mutex.Lock()
	defer metrics.mutex.Unlock()

	metrics.LastActivity = event.Timestamp

	switch event.EventType {
	case EventTypeRequest:
		metrics.RequestsCount++
		metrics.BytesIn += event.BytesIn
		if event.Method != "" {
			metrics.Methods[event.Method]++
		}
		if event.Path != "" {
			metrics.Paths[event.Path]++
		}
		if event.ClientIP != "" {
			metrics.IPs[event.ClientIP]++
		}
		if event.UserAgent != "" {
			metrics.UserAgents[event.UserAgent]++
		}

	case EventTypeResponse:
		metrics.BytesOut += event.BytesOut
		if event.StatusCode > 0 {
			metrics.StatusCodes[event.StatusCode]++
			if event.StatusCode >= 400 {
				metrics.ErrorCount++
			}
		}
		if event.ResponseTime > 0 {
			metrics.TotalResponseTime += event.ResponseTime
			if metrics.MinResponseTime == 0 || event.ResponseTime < metrics.MinResponseTime {
				metrics.MinResponseTime = event.ResponseTime
			}
			if event.ResponseTime > metrics.MaxResponseTime {
				metrics.MaxResponseTime = event.ResponseTime
			}
		}

	case EventTypeConnection:
		metrics.RequestsCount++
		metrics.BytesIn += event.BytesIn
		metrics.BytesOut += event.BytesOut
		if event.ClientIP != "" {
			metrics.IPs[event.ClientIP]++
		}

	case EventTypeError:
		metrics.ErrorCount++
	}
}

// processBatches periodically saves metrics batches to database
func (c *Collector) processBatches() {
	ticker := time.NewTicker(c.batchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.saveBatch()
		}
	}
}

// saveBatch saves current metrics batch to database
func (c *Collector) saveBatch() {
	c.mutex.Lock()

	// Get current batch and create new one
	currentBatch := c.metricsBatch
	c.metricsBatch = make(map[uuid.UUID]*TunnelMetrics)

	c.mutex.Unlock()

	if len(currentBatch) == 0 {
		return
	}

	// Save to database
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for tunnelID, metrics := range currentBatch {
		if err := c.saveMetrics(ctx, metrics); err != nil {
			logger.WithField("tunnel_id", tunnelID.String()).Errorf("Failed to save analytics for tunnel: %v", err)
			c.mutex.Lock()
			c.errors++
			c.mutex.Unlock()
		}
	}

	c.mutex.Lock()
	c.batchesSaved++
	c.mutex.Unlock()

	logger.WithField("tunnels_saved", len(currentBatch)).Info("Saved analytics batch")
}

// saveMetrics saves tunnel metrics to database
func (c *Collector) saveMetrics(ctx context.Context, metrics *TunnelMetrics) error {
	metrics.mutex.RLock()
	defer metrics.mutex.RUnlock()

	// Convert UUID to uuid.UUID
	var pgTunnelID uuid.UUID
	if err := pgTunnelID.Scan(metrics.TunnelID.String()); err != nil {
		return fmt.Errorf("failed to scan tunnel ID: %w", err)
	}

	// Calculate average response time
	var avgResponseTime float32
	if metrics.RequestsCount > 0 {
		avgResponseTime = float32(metrics.TotalResponseTime.Milliseconds()) / float32(metrics.RequestsCount)
	}

	// Convert maps to JSON
	statusCodesJSON, _ := json.Marshal(metrics.StatusCodes)
	methodsJSON, _ := json.Marshal(metrics.Methods)
	pathsJSON, _ := json.Marshal(metrics.Paths)
	ipsJSON, _ := json.Marshal(metrics.IPs)
	userAgentsJSON, _ := json.Marshal(metrics.UserAgents)

	// Insert analytics record
	params := sqlc.CreateTunnelAnalyticsParams{
		TunnelID:        pgTunnelID,
		Timestamp:       pgtype.Timestamptz{Time: metrics.LastActivity, Valid: true},
		RequestsCount:   metrics.RequestsCount,
		BytesIn:         metrics.BytesIn,
		BytesOut:        metrics.BytesOut,
		ResponseTimeAvg: pgtype.Float4{Float32: avgResponseTime, Valid: avgResponseTime > 0},
		ErrorCount:      metrics.ErrorCount,
	}

	if _, err := c.db.Queries.CreateTunnelAnalytics(ctx, params); err != nil {
		return fmt.Errorf("failed to create tunnel analytics: %w", err)
	}

	// Store additional metrics if needed
	// TODO: Create separate tables for detailed breakdowns if required
	_ = statusCodesJSON
	_ = methodsJSON
	_ = pathsJSON
	_ = ipsJSON
	_ = userAgentsJSON

	return nil
}

// processFinalBatch processes any remaining metrics before shutdown
func (c *Collector) processFinalBatch() {
	c.saveBatch()
}

// Helper functions

// copyMap creates a copy of an int64 map
func copyMap(original map[int]int64) map[int]int64 {
	result := make(map[int]int64)
	for k, v := range original {
		result[k] = v
	}
	return result
}

// copyStringMap creates a copy of a string map
func copyStringMap(original map[string]int64) map[string]int64 {
	result := make(map[string]int64)
	for k, v := range original {
		result[k] = v
	}
	return result
}
