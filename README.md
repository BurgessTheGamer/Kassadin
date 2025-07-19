# Kassadin - A Cardano Node Implementation in Zig

<div align="center">

![Zig Version](https://img.shields.io/badge/Zig-0.13.0-orange)
![License](https://img.shields.io/badge/License-MIT-blue)
![Status](https://img.shields.io/badge/Status-Alpha-yellow)

**A high-performance Cardano node implementation written in Zig**

[Features](#features) • [Quick Start](#quick-start) • [Architecture](#architecture) • [Contributing](#contributing)

</div>

## 🚀 Overview

Kassadin is a from-scratch implementation of a Cardano node in the Zig programming language. Our goal is to create a fast, reliable, and easy-to-understand node implementation that can serve as both a production node and a learning resource for the Cardano community.

### Why Kassadin?

- **Performance**: Zig's zero-cost abstractions and manual memory management enable optimal performance
- **Simplicity**: Clean codebase without historical baggage, focused on modern Cardano (Shelley+)
- **Safety**: Zig's compile-time guarantees and explicit error handling reduce bugs
- **Educational**: Well-documented code serves as a reference implementation

## ✨ Features

### Implemented ✅

- **Cryptography**
  - Ed25519 signatures
  - Blake2b hashing (224, 256, custom)
  - Cardano address generation (Shelley)
  - VRF for slot leader election
  - Bech32 encoding/decoding

- **Ledger**
  - UTXO management
  - Transaction validation
  - Multi-asset support (structure)
  - Fee calculation
  - Block structure

- **Consensus**
  - Ouroboros Praos implementation
  - Slot leader election
  - Chain selection (density rule)
  - Fork handling

- **Networking**
  - P2P protocol implementation
  - Peer discovery via DNS
  - Chain synchronization
  - Message encoding/decoding

- **Storage**
  - File-based persistence
  - Block storage
  - UTXO storage
  - Chain state management

### In Progress 🚧

- KES (Key Evolving Signatures)
- Full certificate handling
- Reward calculations
- Testnet connectivity
- Performance optimizations

### Planned 📋

- Plutus script execution
- Hardware wallet support
- Prometheus metrics
- Docker deployment
- Web dashboard

## 🏃 Quick Start

### Prerequisites

- Zig 0.13.0 or later
- libsodium
- POSIX-compliant OS (Linux, macOS, BSD)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/kassadin.git
cd kassadin

# Install dependencies (macOS)
brew install libsodium

# Install dependencies (Ubuntu/Debian)
sudo apt-get install libsodium-dev

# Build the node
zig build -Doptimize=ReleaseFast

# Run tests
zig build test

# Run the node
./zig-out/bin/kassadin --network testnet
```

### Running Demos

Kassadin includes several demos to showcase its functionality:

```bash
# Cryptography demo
zig build crypto-test

# Ledger demo (UTXO transactions)
zig build ledger-demo

# Consensus demo (slot leader election)
zig build consensus-demo

# Network demo (P2P protocol)
zig build network-demo

# Storage demo (persistence)
zig build storage-demo

# Full integration demo
zig build integration-demo
```

## 🏗️ Architecture

Kassadin is organized into modular components:

```
src/
├── crypto/          # Cryptographic primitives
│   ├── crypto.zig   # Main crypto API
│   ├── sodium.zig   # libsodium bindings
│   ├── address.zig  # Address generation
│   ├── bech32.zig   # Bech32 encoding
│   └── vrf.zig      # VRF implementation
├── ledger/          # Blockchain ledger
│   ├── ledger.zig   # UTXO management
│   ├── transaction.zig # Transaction types
│   └── block.zig    # Block structure
├── consensus/       # Consensus mechanism
│   ├── praos.zig    # Ouroboros Praos
│   └── chain.zig    # Chain selection
├── network/         # P2P networking
│   ├── protocol.zig # Wire protocol
│   ├── peer.zig     # Peer management
│   ├── sync.zig     # Chain sync
│   └── dns.zig      # DNS resolution
├── storage/         # Persistence layer
│   ├── storage.zig  # Storage interface
│   └── file_store.zig # File backend
└── node.zig         # Main node coordinator
```

### Design Principles

1. **Modularity**: Each component has clear boundaries and interfaces
2. **Testability**: Comprehensive test coverage for all modules
3. **Performance**: Zero-allocation APIs where possible
4. **Safety**: Explicit error handling, no hidden control flow
5. **Clarity**: Self-documenting code with meaningful names

## 📊 Performance

Preliminary benchmarks on commodity hardware:

- **Signature Verification**: ~50,000 ops/sec
- **Transaction Validation**: ~10,000 tx/sec
- **Block Processing**: ~1,000 blocks/sec
- **Memory Usage**: <500MB for full node

*Note: These are early numbers and will improve with optimization*

## 🛠️ Development

### Building from Source

```bash
# Debug build (with safety checks)
zig build

# Release build (optimized)
zig build -Doptimize=ReleaseFast

# Small build (size-optimized)
zig build -Doptimize=ReleaseSmall
```

### Running Tests

```bash
# Run all tests
zig build test

# Run specific module tests
zig test src/crypto/crypto.zig
zig test src/ledger/ledger.zig
```

### Code Style

We follow Zig's standard formatting:

```bash
# Format all code
zig fmt src/
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details.

### Areas We Need Help

- Protocol testing against mainnet
- Performance optimization
- Documentation improvements
- Cross-platform testing
- Security auditing

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [Development Guide](docs/development.md)
- [API Reference](docs/api.md)
- [Protocol Specification](docs/protocol.md)

## 🔒 Security

Kassadin is alpha software and has not been audited. Do not use it for mainnet operations with real funds yet.

To report security issues, please email security@kassadin.io

## 📄 License

Kassadin is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## 🙏 Acknowledgments

- The Cardano Foundation for protocol specifications
- Input Output Global for reference implementations
- The Zig community for an amazing language
- All contributors and testers

---

<div align="center">

**Built with ❤️ and Zig**

[Website](https://kassadin.io) • [Discord](https://discord.gg/kassadin) • [Twitter](https://twitter.com/kassadin_io)

</div>