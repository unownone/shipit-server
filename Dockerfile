# Build stage
FROM golang:1.24-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go modules files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o shipit-server cmd/server/main.go

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata curl

# Create non-root user
RUN addgroup -S shipit && adduser -S shipit -G shipit

# Set working directory
WORKDIR /app

# Copy binary from builder stage
COPY --from=builder /app/shipit-server .

# Copy configuration files
COPY --from=builder /app/configs ./configs

# Change ownership to non-root user
RUN chown -R shipit:shipit /app

# Switch to non-root user
USER shipit

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Run the application
CMD ["./shipit-server"] 