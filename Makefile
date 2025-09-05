# Makefile for Elise Project

.PHONY: lab lab-down help

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

# Show help
help:
	@echo "Available targets:"
	@echo "  lab      - Start the vulnerable lab environment"
	@echo "  lab-down - Stop the vulnerable lab environment"
	@echo "  help     - Show this help message"
