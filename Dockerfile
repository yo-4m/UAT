FROM rust:latest

WORKDIR /app

# Install necessary tools
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    netcat-traditional \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY . .

# Build will be done via volume mount during development
CMD ["cargo", "run"]
