#!/bin/bash
set -e

echo "QuicTor PT - Development Environment Setup"
echo "==========================================="

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Rust is not installed."
    echo "Would you like to install it? (y/n)"
    read -r response
    if [[ "$response" =~ ^[Yy]$ ]]; then
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        source $HOME/.cargo/env
    else
        echo "Rust is required. Please install it from https://rustup.rs"
        exit 1
    fi
fi

echo "✓ Rust: $(rustc --version)"

# Build
echo ""
echo "Building project..."
cargo build

echo ""
echo "✓ Setup complete!"
echo ""
echo "You can run the following commands:"
echo "  cargo run --bin server    # Test server"
echo "  cargo run --bin client    # Test client"
echo "  cargo run --bin quictor-pt # Pluggable Transport"
