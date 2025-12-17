#!/bin/bash

set -e

echo "Starting Vulnerable E-Commerce Application..."
echo ""

cd "$(dirname "$0")/.."

docker-compose down 2>/dev/null || true

echo "Building and starting services..."
docker-compose up -d --build

echo ""
echo "Waiting for services to be ready..."
sleep 10

echo ""
echo "Services started successfully!"
echo ""
echo "Access the application:"
echo "  Frontend:      http://localhost"
echo "  Backend API:   http://localhost:8081/api"
echo "  Log4Shell:     http://localhost:8083"
echo ""
echo "View logs:"
echo "  docker-compose logs -f"
echo ""
echo "Stop services:"
echo "  docker-compose down"
