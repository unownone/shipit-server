#!/bin/bash

# Generate Swagger documentation for ShipIt Server API
# This script regenerates the Swagger documentation from Go code comments

set -e

echo "🔍 Generating Swagger documentation..."

# Check if swag is installed
if ! command -v swag &> /dev/null; then
    echo "📦 Installing swag..."
    go install github.com/swaggo/swag/cmd/swag@latest
fi

# Generate documentation
echo "📝 Running swag init..."
swag init -g cmd/server/main.go -o docs

echo "✅ Documentation generated successfully!"
echo "📁 Files created:"
echo "   - docs/docs.go"
echo "   - docs/swagger.json"
echo "   - docs/swagger.yaml"

echo ""
echo "🌐 To view the documentation:"
echo "   1. Start the server: go run cmd/server/main.go"
echo "   2. Open: http://localhost:8080/swagger/index.html"
echo ""
echo "📚 Documentation will be automatically deployed to GitHub Pages via CI/CD" 