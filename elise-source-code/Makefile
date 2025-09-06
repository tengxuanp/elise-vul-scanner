# Makefile for Elise Project

.PHONY: lab lab-down playwright models docker-up docker-down docker-build docker-logs help

# Start the vulnerable lab environment
lab:
	@echo "Starting vulnerable lab environment..."
	docker compose up -d lab
	@echo "Initializing database..."
	python3 lab/init_db.py
	@echo "Lab is running at http://localhost:5001/"
	@echo "⚠️  WARNING: This is intentionally vulnerable - for local testing only!"

# Stop the vulnerable lab environment
lab-down:
	@echo "Stopping vulnerable lab environment..."
	docker compose rm -sf lab

# Install Playwright browsers for development
playwright:
	@echo "Installing Playwright browsers..."
	python3 -m playwright install --with-deps chromium
	@echo "✅ Playwright browsers installed successfully"

# Train ML models with synthetic data
models:
	@echo "Training ML models with synthetic data..."
	cd backend && python -m modules.ml.train_minimal
	@echo "✅ ML models trained successfully"
	@echo "📊 Check /api/healthz to verify ml_ready=true"

# Docker commands
docker-build:
	@echo "Building all Docker images..."
	docker compose build

docker-up:
	@echo "Starting full Elise stack (lab + backend + frontend)..."
	docker compose up -d
	@echo "✅ Elise stack started!"
	@echo "🌐 Frontend: http://localhost:3000"
	@echo "🔧 Backend API: http://localhost:8000"
	@echo "🧪 Lab: http://localhost:5001"
	@echo "📊 API Docs: http://localhost:8000/docs"

docker-down:
	@echo "Stopping Elise stack..."
	docker compose down
	@echo "✅ Elise stack stopped"

docker-logs:
	@echo "Showing logs for all services..."
	docker compose logs -f

# Show help
help:
	@echo "Available targets:"
	@echo "  lab          - Start the vulnerable lab environment"
	@echo "  lab-down     - Stop the vulnerable lab environment"
	@echo "  playwright   - Install Playwright browsers for development"
	@echo "  models       - Train ML models with synthetic data"
	@echo "  docker-build - Build all Docker images"
	@echo "  docker-up    - Start full Elise stack (lab + backend + frontend)"
	@echo "  docker-down  - Stop Elise stack"
	@echo "  docker-logs  - Show logs for all services"
	@echo "  help         - Show this help message"
