.PHONY: all build test clean run fmt setup install

# Default target
all: build

# Build the project
build:
	zig build

# Build optimized release
release:
	zig build -Doptimize=ReleaseFast

# Run tests
test:
	zig build test

# Clean build artifacts
clean:
	rm -rf zig-out zig-cache .zig-cache

# Run the node
run: build
	./zig-out/bin/kassadin

# Format code
fmt:
	zig fmt src/

# Check formatting
fmt-check:
	zig build fmt-check

# Setup development environment
setup:
	./scripts/setup.sh

# Install to system (requires sudo on some systems)
install: release
	@echo "Installing Kassadin to /usr/local/bin..."
	@sudo cp zig-out/bin/kassadin /usr/local/bin/
	@echo "Installation complete! Run 'kassadin --help' to get started."

# Development helpers
dev-mainnet: build
	./zig-out/bin/kassadin --network mainnet --log-level debug

dev-testnet: build
	./zig-out/bin/kassadin --network testnet --log-level debug

# Show help
help:
	@echo "Kassadin Development Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  make build      - Build debug version"
	@echo "  make release    - Build optimized version"
	@echo "  make test       - Run tests"
	@echo "  make clean      - Clean build artifacts"
	@echo "  make run        - Build and run"
	@echo "  make fmt        - Format code"
	@echo "  make setup      - Setup development environment"
	@echo "  make install    - Install to system"
	@echo ""
	@echo "Development targets:"
	@echo "  make dev-mainnet - Run with mainnet config (debug)"
	@echo "  make dev-testnet - Run with testnet config (debug)"