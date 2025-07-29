// Package agent handles the data plane protocol and agent connections
// This implements the custom TLS protocol for high-throughput data forwarding
package agent

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/uuid"
)

// MessageType represents the type of message in the data plane protocol
type MessageType byte

const (
	// MessageTypeTunnelRegistration - Client registers a tunnel connection
	MessageTypeTunnelRegistration MessageType = 0x01

	// MessageTypeDataForward - Server forwards visitor data to client
	MessageTypeDataForward MessageType = 0x02

	// MessageTypeDataResponse - Client sends response data back to server
	MessageTypeDataResponse MessageType = 0x03

	// MessageTypeConnectionClose - Close a specific connection
	MessageTypeConnectionClose MessageType = 0x04

	// MessageTypeHeartbeat - Keepalive message
	MessageTypeHeartbeat MessageType = 0x05

	// MessageTypeError - Error notification
	MessageTypeError MessageType = 0x06

	// MessageTypeAcknowledge - Acknowledgment message
	MessageTypeAcknowledge MessageType = 0x07
)

// Message represents a data plane protocol message
// Format: [MessageType:1][TunnelID:16][PayloadLength:4][Payload:variable]
type Message struct {
	Type     MessageType
	TunnelID uuid.UUID
	Payload  []byte
}

// TunnelRegistrationPayload represents tunnel registration data
type TunnelRegistrationPayload struct {
	Protocol       string `json:"protocol"`        // "http" or "tcp"
	LocalPort      int32  `json:"local_port"`      // Port on client side
	Subdomain      string `json:"subdomain"`       // For HTTP tunnels
	PublicPort     int32  `json:"public_port"`     // For TCP tunnels
	MaxConnections int    `json:"max_connections"` // Connection pool size
}

// DataForwardPayload represents data to be forwarded to client
type DataForwardPayload struct {
	ConnectionID string            `json:"connection_id"`     // Unique connection identifier
	RequestID    string            `json:"request_id"`        // Unique request identifier
	Data         []byte            `json:"data"`              // Raw data to forward
	Headers      map[string]string `json:"headers,omitempty"` // HTTP headers if applicable
	Method       string            `json:"method,omitempty"`  // HTTP method if applicable
	Path         string            `json:"path,omitempty"`    // HTTP path if applicable
}

// DataResponsePayload represents response data from client
type DataResponsePayload struct {
	ConnectionID string            `json:"connection_id"`         // Connection identifier
	RequestID    string            `json:"request_id"`            // Request identifier
	Data         []byte            `json:"data"`                  // Response data
	StatusCode   int               `json:"status_code,omitempty"` // HTTP status code if applicable
	Headers      map[string]string `json:"headers,omitempty"`     // HTTP response headers if applicable
}

// ConnectionClosePayload represents connection close notification
type ConnectionClosePayload struct {
	ConnectionID string `json:"connection_id"` // Connection to close
	Reason       string `json:"reason"`        // Reason for closing
}

// HeartbeatPayload represents heartbeat data
type HeartbeatPayload struct {
	Timestamp     int64 `json:"timestamp"`      // Unix timestamp
	ActiveConns   int   `json:"active_conns"`   // Number of active connections
	TotalRequests int64 `json:"total_requests"` // Total requests processed
}

// ErrorPayload represents error information
type ErrorPayload struct {
	Code    string `json:"code"`              // Error code
	Message string `json:"message"`           // Error message
	Details string `json:"details,omitempty"` // Additional details
}

// AcknowledgePayload represents acknowledgment data
type AcknowledgePayload struct {
	MessageType MessageType `json:"message_type"`      // Type of message being acknowledged
	Success     bool        `json:"success"`           // Whether operation was successful
	Message     string      `json:"message,omitempty"` // Optional message
}

// Constants for protocol
const (
	// MessageHeaderSize is the size of the message header (type + tunnel_id + length)
	MessageHeaderSize = 1 + 16 + 4 // 21 bytes

	// MaxPayloadSize is the maximum payload size (1MB)
	MaxPayloadSize = 1024 * 1024

	// DefaultConnectionPoolSize is the default number of connections per tunnel
	DefaultConnectionPoolSize = 10

	// ProtocolVersion is the current protocol version
	ProtocolVersion = 1
)

// WriteMessage writes a message to the writer using the data plane protocol format
func WriteMessage(w io.Writer, msg *Message) error {
	// Validate payload size
	if len(msg.Payload) > MaxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes (max %d)", len(msg.Payload), MaxPayloadSize)
	}

	// Write message type (1 byte)
	if err := binary.Write(w, binary.BigEndian, msg.Type); err != nil {
		return fmt.Errorf("failed to write message type: %w", err)
	}

	// Write tunnel ID (16 bytes)
	tunnelIDBytes, err := msg.TunnelID.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal tunnel ID: %w", err)
	}
	if _, err := w.Write(tunnelIDBytes); err != nil {
		return fmt.Errorf("failed to write tunnel ID: %w", err)
	}

	// Write payload length (4 bytes)
	payloadLength := uint32(len(msg.Payload))
	if err := binary.Write(w, binary.BigEndian, payloadLength); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// ReadMessage reads a message from the reader using the data plane protocol format
func ReadMessage(r io.Reader) (*Message, error) {
	msg := &Message{}

	// Read message type (1 byte)
	if err := binary.Read(r, binary.BigEndian, &msg.Type); err != nil {
		return nil, fmt.Errorf("failed to read message type: %w", err)
	}

	// Read tunnel ID (16 bytes)
	tunnelIDBytes := make([]byte, 16)
	if _, err := io.ReadFull(r, tunnelIDBytes); err != nil {
		return nil, fmt.Errorf("failed to read tunnel ID: %w", err)
	}
	if err := msg.TunnelID.UnmarshalBinary(tunnelIDBytes); err != nil {
		return nil, fmt.Errorf("failed to unmarshal tunnel ID: %w", err)
	}

	// Read payload length (4 bytes)
	var payloadLength uint32
	if err := binary.Read(r, binary.BigEndian, &payloadLength); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}

	// Validate payload length
	if payloadLength > MaxPayloadSize {
		return nil, fmt.Errorf("payload too large: %d bytes (max %d)", payloadLength, MaxPayloadSize)
	}

	// Read payload
	if payloadLength > 0 {
		msg.Payload = make([]byte, payloadLength)
		if _, err := io.ReadFull(r, msg.Payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return msg, nil
}

// IsValidMessageType checks if a message type is valid
func IsValidMessageType(msgType MessageType) bool {
	switch msgType {
	case MessageTypeTunnelRegistration,
		MessageTypeDataForward,
		MessageTypeDataResponse,
		MessageTypeConnectionClose,
		MessageTypeHeartbeat,
		MessageTypeError,
		MessageTypeAcknowledge:
		return true
	default:
		return false
	}
}

// String returns a string representation of the message type
func (mt MessageType) String() string {
	switch mt {
	case MessageTypeTunnelRegistration:
		return "TunnelRegistration"
	case MessageTypeDataForward:
		return "DataForward"
	case MessageTypeDataResponse:
		return "DataResponse"
	case MessageTypeConnectionClose:
		return "ConnectionClose"
	case MessageTypeHeartbeat:
		return "Heartbeat"
	case MessageTypeError:
		return "Error"
	case MessageTypeAcknowledge:
		return "Acknowledge"
	default:
		return fmt.Sprintf("Unknown(%d)", byte(mt))
	}
}

// String returns a string representation of the message
func (m *Message) String() string {
	return fmt.Sprintf("Message{Type: %s, TunnelID: %s, PayloadSize: %d}",
		m.Type.String(), m.TunnelID.String(), len(m.Payload))
}
