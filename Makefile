BINARY := llm-hasher
BUILD_DIR := .build
GO := go
GOFLAGS := -ldflags="-s -w"

.PHONY: build run setup test clean docker-up docker-down

## build: compile the binary
build:
	mkdir -p $(BUILD_DIR)
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/llm-hasher

## run: build and run with default config
run: build
	CONFIG_PATH=configs/config.yaml $(BUILD_DIR)/$(BINARY)

## setup: install Ollama if missing, pull model, copy config, build binary
setup:
	@echo "==> Checking Ollama..."
	@if ! command -v ollama > /dev/null 2>&1; then \
		echo "==> Installing Ollama..."; \
		curl -fsSL https://ollama.ai/install.sh | sh; \
	else \
		echo "==> Ollama already installed"; \
	fi
	@echo "==> Starting Ollama in background..."
	@ollama serve &>/dev/null & sleep 2
	@echo "==> Pulling llama3.2:3b model (this may take a few minutes)..."
	@ollama pull llama3.2:3b
	@echo "==> Setting up config..."
	@if [ ! -f configs/config.yaml ]; then \
		cp configs/config.example.yaml configs/config.yaml; \
		echo "==> Created configs/config.yaml (edit as needed)"; \
	fi
	@mkdir -p data
	@$(MAKE) build
	@echo ""
	@echo "Setup complete! Run 'make run' to start the server."

## test: run all tests
test:
	$(GO) test ./...

## test-verbose: run tests with output
test-verbose:
	$(GO) test -v ./...

## lint: run go vet
lint:
	$(GO) vet ./...

## clean: remove build artifacts
clean:
	rm -rf $(BUILD_DIR)

## docker-up: start all services with docker-compose
docker-up:
	@if [ ! -f configs/config.yaml ]; then \
		cp configs/config.example.yaml configs/config.yaml; \
	fi
	@mkdir -p data
	docker compose up -d
	@echo ""
	@echo "Services starting... Ollama model pull may take a few minutes."
	@echo "Check status: docker compose logs -f"
	@echo "Health:       curl http://localhost:8080/healthz"

## docker-down: stop all services
docker-down:
	docker compose down

## docker-logs: tail service logs
docker-logs:
	docker compose logs -f llm-hasher

help:
	@grep -E '^## ' Makefile | sed 's/## //' | column -t -s ':'
