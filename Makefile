# Makefile for Elise Project

.PHONY: lab lab-down dvwa-up dvwa-down benchmark-up benchmark-down labs-up labs-down labs-logs playwright models docker-up docker-down docker-build docker-logs help

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
	@echo "  dvwa-up      - Start DVWA (PHP/Apache + MariaDB)"
	@echo "  dvwa-down    - Stop DVWA"
	@echo "  benchmark-up - Start OWASP Benchmark (Java/Tomcat, HTTPS:8443)"
	@echo "  benchmark-down- Stop OWASP Benchmark"
	@echo "  labs-up      - Start both DVWA and OWASP Benchmark"
	@echo "  labs-down    - Stop both DVWA and OWASP Benchmark"
	@echo "  labs-logs    - Tail logs for DVWA/Benchmark labs"
	@echo "  playwright   - Install Playwright browsers for development"
	@echo "  models       - Train ML models with synthetic data"
	@echo "  docker-build - Build all Docker images"
	@echo "  docker-up    - Start full Elise stack (lab + backend + frontend)"
	@echo "  docker-down  - Stop Elise stack"
	@echo "  docker-logs  - Show logs for all services"
	@echo "  help         - Show this help message"

# === Third-party Labs ===

dvwa-up:
	@echo "Starting DVWA (http://localhost:4280)..."
	docker compose -f labs/docker-compose.yml up -d dvwa
	@echo "✅ DVWA started. Open http://localhost:4280"

dvwa-down:
	@echo "Stopping DVWA..."
	docker compose -f labs/docker-compose.yml rm -sf dvwa dvwa-db
	@echo "✅ DVWA stopped"

benchmark-up:
	@echo "Starting OWASP Benchmark (https://localhost:8443/benchmark/)..."
	docker compose -f labs/docker-compose.yml up -d owasp-benchmark
	@echo "⏳ First start may take several minutes (Maven build + Tomcat download)"
	@echo "🔐 The app uses a self-signed cert; your browser will warn on HTTPS"
	@echo "✅ After healthy, open https://localhost:8443/benchmark/"

benchmark-down:
	@echo "Stopping OWASP Benchmark..."
	docker compose -f labs/docker-compose.yml rm -sf owasp-benchmark
	@echo "✅ OWASP Benchmark stopped"

labs-up:
	@echo "Starting DVWA and OWASP Benchmark..."
	docker compose -f labs/docker-compose.yml up -d
	@echo "✅ Labs started"
	@echo "  DVWA:            http://localhost:4280"
	@echo "  OWASP Benchmark: https://localhost:8443/benchmark/ (self-signed cert)"

labs-down:
	@echo "Stopping DVWA and OWASP Benchmark..."
	docker compose -f labs/docker-compose.yml down
	@echo "✅ Labs stopped"

labs-logs:
	@echo "Tailing logs for third-party labs..."
	docker compose -f labs/docker-compose.yml logs -f
