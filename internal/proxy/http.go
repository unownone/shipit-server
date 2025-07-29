// Package proxy provides HTTP and TCP proxy functionality for routing visitor traffic
package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/unwonone/shipit-server/internal/config"
	"github.com/unwonone/shipit-server/internal/logger"
	"github.com/unwonone/shipit-server/internal/tunnel"
)

// HTTPProxy handles HTTP/HTTPS traffic routing to tunnels
type HTTPProxy struct {
	tunnelManager *tunnel.TunnelManager
	config        *config.Config

	// HTTP servers
	httpServer  *http.Server
	httpsServer *http.Server

	// Server control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Statistics
	totalRequests  int64
	totalBytesIn   int64
	totalBytesOut  int64
	activeRequests int32
	totalErrors    int64

	mutex sync.RWMutex
}

// RequestContext holds information about a proxied request
type RequestContext struct {
	RequestID     string
	TunnelID      uuid.UUID
	Subdomain     string
	StartTime     time.Time
	ClientIP      string
	UserAgent     string
	Method        string
	Path          string
	ContentLength int64
}

// NewHTTPProxy creates a new HTTP proxy
func NewHTTPProxy(tunnelManager *tunnel.TunnelManager, config *config.Config) *HTTPProxy {
	ctx, cancel := context.WithCancel(context.Background())

	return &HTTPProxy{
		tunnelManager: tunnelManager,
		config:        config,
		ctx:           ctx,
		cancel:        cancel,
	}
}

// Start starts the HTTP and HTTPS proxy servers
func (hp *HTTPProxy) Start() error {
	// Create HTTP handler
	handler := http.HandlerFunc(hp.handleHTTPRequest)

	// Start HTTP server (port 80)
	hp.httpServer = &http.Server{
		Addr:           fmt.Sprintf(":%d", hp.config.Server.HTTPPort),
		Handler:        handler,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	// Start HTTP server in goroutine
	hp.wg.Add(1)
	go func() {
		defer hp.wg.Done()
		logger.WithField("port", hp.config.Server.HTTPPort).Info("HTTP proxy server starting")
		if err := hp.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.WithError(err).Error("HTTP proxy server error")
		}
	}()

	// Start HTTPS server (port 443) if TLS is configured
	if hp.config.TLS.CertFile != "" && hp.config.TLS.KeyFile != "" {
		hp.httpsServer = &http.Server{
			Addr:           fmt.Sprintf(":%d", hp.config.Server.HTTPSPort),
			Handler:        handler,
			ReadTimeout:    30 * time.Second,
			WriteTimeout:   30 * time.Second,
			IdleTimeout:    60 * time.Second,
			MaxHeaderBytes: 1 << 20, // 1MB
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		}

		hp.wg.Add(1)
		go func() {
			defer hp.wg.Done()
			logger.WithField("port", hp.config.Server.HTTPSPort).Info("HTTPS proxy server starting")
			if err := hp.httpsServer.ListenAndServeTLS(hp.config.TLS.CertFile, hp.config.TLS.KeyFile); err != nil && err != http.ErrServerClosed {
				logger.WithError(err).Error("HTTPS proxy server error")
			}
		}()
	}

	logger.Get().Info("HTTP proxy servers started")
	return nil
}

// Stop gracefully stops the HTTP proxy servers
func (hp *HTTPProxy) Stop() error {
	logger.Get().Info("Stopping HTTP proxy servers")

	// Cancel context
	hp.cancel()

	// Shutdown servers with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if hp.httpServer != nil {
		if err := hp.httpServer.Shutdown(ctx); err != nil {
			logger.WithError(err).Error("Error shutting down HTTP server")
		}
	}

	// Shutdown HTTPS server
	if hp.httpsServer != nil {
		if err := hp.httpsServer.Shutdown(ctx); err != nil {
			logger.WithError(err).Error("Error shutting down HTTPS server")
		}
	}

	// Wait for all goroutines to finish
	hp.wg.Wait()

	logger.Get().Info("HTTP proxy servers stopped")
	return nil
}

// handleHTTPRequest handles incoming HTTP requests and routes them to tunnels
func (hp *HTTPProxy) handleHTTPRequest(w http.ResponseWriter, r *http.Request) {
	// Update statistics
	hp.mutex.Lock()
	hp.totalRequests++
	hp.activeRequests++
	requestID := fmt.Sprintf("req_%d_%d", time.Now().UnixNano(), hp.totalRequests)
	hp.mutex.Unlock()

	defer func() {
		hp.mutex.Lock()
		hp.activeRequests--
		hp.mutex.Unlock()
	}()

	// Create request context
	reqCtx := &RequestContext{
		RequestID:     requestID,
		StartTime:     time.Now(),
		ClientIP:      getClientIP(r),
		UserAgent:     r.UserAgent(),
		Method:        r.Method,
		Path:          r.URL.Path,
		ContentLength: r.ContentLength,
	}

	logger.WithFields(map[string]interface{}{
		"request_id": reqCtx.RequestID,
		"method":     reqCtx.Method,
		"path":       reqCtx.Path,
		"client_ip":  reqCtx.ClientIP,
	}).Debug("HTTP request received")

	// Extract subdomain from Host header
	subdomain, err := hp.extractSubdomain(r.Host)
	if err != nil {
		hp.handleError(w, reqCtx, http.StatusBadRequest, "Invalid host header", err)
		return
	}

	if subdomain == "" {
		hp.handleError(w, reqCtx, http.StatusNotFound, "Subdomain not found", fmt.Errorf("no subdomain in host: %s", r.Host))
		return
	}

	reqCtx.Subdomain = subdomain

	// Find tunnel by subdomain
	tunnelObj, err := hp.tunnelManager.GetTunnelBySubdomain(subdomain)
	if err != nil {
		hp.handleError(w, reqCtx, http.StatusNotFound, "Tunnel not found", err)
		return
	}

	reqCtx.TunnelID = tunnelObj.ID

	// Check tunnel state
	if tunnelObj.State != tunnel.StateActive {
		hp.handleError(w, reqCtx, http.StatusServiceUnavailable, "Tunnel not available", fmt.Errorf("tunnel state: %s", tunnelObj.State))
		return
	}

	// Read request body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		hp.handleError(w, reqCtx, http.StatusBadRequest, "Failed to read request body", err)
		return
	}
	r.Body.Close()

	// Create forward request
	forwardReq := &tunnel.ForwardRequest{
		ConnectionID: fmt.Sprintf("conn_%s", requestID),
		RequestID:    requestID,
		Data:         body,
		Headers:      convertHeaders(r.Header),
		Method:       r.Method,
		Path:         r.URL.RequestURI(),
		ResponseChan: make(chan *tunnel.ForwardResponse, 1),
	}

	// Forward request through tunnel
	response, err := hp.tunnelManager.ForwardRequest(tunnelObj.ID, forwardReq)
	if err != nil {
		hp.handleError(w, reqCtx, http.StatusBadGateway, "Failed to forward request", err)
		return
	}

	// Handle response
	hp.handleResponse(w, reqCtx, response)

	// Log completion
	duration := time.Since(reqCtx.StartTime)
	logger.WithFields(map[string]interface{}{
		"request_id": reqCtx.RequestID,
		"duration":   duration.String(),
	}).Info("Request completed")
}

// extractSubdomain extracts the subdomain from the host header
func (hp *HTTPProxy) extractSubdomain(host string) (string, error) {
	// Remove port if present
	if colonIndex := strings.Index(host, ":"); colonIndex != -1 {
		host = host[:colonIndex]
	}

	// Convert to lowercase
	host = strings.ToLower(host)

	// Check if host matches our domain
	serverDomain := strings.ToLower(hp.config.Server.Domain)

	// Handle exact domain match (no subdomain)
	if host == serverDomain {
		return "", nil
	}

	// Check if host ends with our domain
	domainSuffix := "." + serverDomain
	if !strings.HasSuffix(host, domainSuffix) {
		return "", fmt.Errorf("host %s does not match domain %s", host, serverDomain)
	}

	// Extract subdomain
	subdomain := host[:len(host)-len(domainSuffix)]

	// Validate subdomain
	if subdomain == "" {
		return "", nil
	}

	// Basic subdomain validation
	if strings.Contains(subdomain, ".") {
		return "", fmt.Errorf("nested subdomains not supported: %s", subdomain)
	}

	return subdomain, nil
}

// handleError handles errors and sends appropriate responses
func (hp *HTTPProxy) handleError(w http.ResponseWriter, reqCtx *RequestContext, statusCode int, message string, err error) {
	hp.mutex.Lock()
	hp.totalErrors++
	hp.mutex.Unlock()

	logger.WithField("request_id", reqCtx.RequestID).WithError(err).Error(message)

	// Set content type
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Shipit-Error", "true")

	// Write status code
	w.WriteHeader(statusCode)

	// Write error page
	errorHTML := hp.generateErrorPage(statusCode, message, reqCtx)
	w.Write([]byte(errorHTML))
}

// handleResponse handles successful responses from tunnels
func (hp *HTTPProxy) handleResponse(w http.ResponseWriter, reqCtx *RequestContext, response *tunnel.ForwardResponse) {
	if response.Error != nil {
		hp.handleError(w, reqCtx, http.StatusBadGateway, "Tunnel response error", response.Error)
		return
	}

	// Set response headers
	for key, value := range response.Headers {
		w.Header().Set(key, value)
	}

	// Set status code
	statusCode := response.StatusCode
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	w.WriteHeader(statusCode)

	// Write response body
	if len(response.Data) > 0 {
		bytesWritten, err := w.Write(response.Data)
		if err != nil {
			logger.WithField("request_id", reqCtx.RequestID).WithError(err).Error("Error writing response")
			return
		}

		// Update statistics
		hp.mutex.Lock()
		hp.totalBytesIn += int64(len(reqCtx.Path)) // Approximate request size
		hp.totalBytesOut += int64(bytesWritten)
		hp.mutex.Unlock()
	}
}

// generateErrorPage generates an HTML error page
func (hp *HTTPProxy) generateErrorPage(statusCode int, message string, reqCtx *RequestContext) string {
	statusText := http.StatusText(statusCode)
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
    <title>%d %s - ShipIt</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 600px; margin: 0 auto; }
        .error-code { font-size: 72px; font-weight: bold; color: #e74c3c; margin: 0; }
        .error-message { font-size: 24px; color: #333; margin: 10px 0; }
        .description { color: #666; margin: 20px 0; }
        .details { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 20px 0; }
        .footer { margin-top: 40px; color: #999; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <h1 class="error-code">%d</h1>
        <h2 class="error-message">%s</h2>
        <p class="description">%s</p>
        <div class="details">
            <strong>Request ID:</strong> %s<br>
            <strong>Subdomain:</strong> %s<br>
            <strong>Timestamp:</strong> %s
        </div>
        <div class="footer">
            Powered by ShipIt - Secure Tunneling Service
        </div>
    </div>
</body>
</html>`, statusCode, statusText, statusCode, statusText, message, reqCtx.RequestID, reqCtx.Subdomain, reqCtx.StartTime.Format(time.RFC3339))
}

// GetStats returns statistics about the HTTP proxy
func (hp *HTTPProxy) GetStats() HTTPProxyStats {
	hp.mutex.RLock()
	defer hp.mutex.RUnlock()

	return HTTPProxyStats{
		TotalRequests:  hp.totalRequests,
		ActiveRequests: hp.activeRequests,
		TotalBytesIn:   hp.totalBytesIn,
		TotalBytesOut:  hp.totalBytesOut,
		TotalErrors:    hp.totalErrors,
	}
}

// HTTPProxyStats represents statistics for the HTTP proxy
type HTTPProxyStats struct {
	TotalRequests  int64
	ActiveRequests int32
	TotalBytesIn   int64
	TotalBytesOut  int64
	TotalErrors    int64
}

// Helper functions

// getClientIP extracts the client IP address from the request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header (from load balancers)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the chain
		if commaIndex := strings.Index(xff, ","); commaIndex != -1 {
			return strings.TrimSpace(xff[:commaIndex])
		}
		return strings.TrimSpace(xff)
	}

	// Check X-Real-IP header (from nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return strings.TrimSpace(xri)
	}

	// Fall back to remote address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// convertHeaders converts http.Header to map[string]string
func convertHeaders(headers http.Header) map[string]string {
	result := make(map[string]string)
	for key, values := range headers {
		if len(values) > 0 {
			result[key] = values[0] // Take the first value for simplicity
		}
	}
	return result
}

// CreateReverseProxy creates a reverse proxy handler (alternative implementation)
// This can be used instead of the custom forwarding logic for simpler HTTP-only tunnels
func (hp *HTTPProxy) CreateReverseProxy(tunnelID uuid.UUID) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			// Modify request to forward to the tunnel
			req.URL.Scheme = "http"
			req.URL.Host = "localhost" // This would be dynamically determined
			req.Header.Set("X-Tunnel-ID", tunnelID.String())
			req.Header.Set("X-Forwarded-Proto", "https")
		},
		Transport: &TunnelTransport{
			tunnelManager: hp.tunnelManager,
			tunnelID:      tunnelID,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			logger.WithError(err).Error("Reverse proxy error")
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}
}

// TunnelTransport implements http.RoundTripper for tunnel communication
type TunnelTransport struct {
	tunnelManager *tunnel.TunnelManager
	tunnelID      uuid.UUID
}

// RoundTrip implements the http.RoundTripper interface
func (tt *TunnelTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Read request body
	var body []byte
	if req.Body != nil {
		var err error
		body, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body.Close()
	}

	// Create forward request
	forwardReq := &tunnel.ForwardRequest{
		ConnectionID: fmt.Sprintf("conn_%d", time.Now().UnixNano()),
		RequestID:    fmt.Sprintf("req_%d", time.Now().UnixNano()),
		Data:         body,
		Headers:      convertHeaders(req.Header),
		Method:       req.Method,
		Path:         req.URL.RequestURI(),
		ResponseChan: make(chan *tunnel.ForwardResponse, 1),
	}

	// Forward through tunnel
	response, err := tt.tunnelManager.ForwardRequest(tt.tunnelID, forwardReq)
	if err != nil {
		return nil, fmt.Errorf("tunnel forward failed: %w", err)
	}

	if response.Error != nil {
		return nil, fmt.Errorf("tunnel response error: %w", response.Error)
	}

	// Convert to HTTP response
	httpResp := &http.Response{
		StatusCode:    response.StatusCode,
		Status:        fmt.Sprintf("%d %s", response.StatusCode, http.StatusText(response.StatusCode)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(response.Data))),
		ContentLength: int64(len(response.Data)),
		Request:       req,
	}

	// Set response headers
	for key, value := range response.Headers {
		httpResp.Header.Set(key, value)
	}

	return httpResp, nil
}
