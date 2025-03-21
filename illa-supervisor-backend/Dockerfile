# Build stage
FROM golang:1.18-alpine AS builder

# Install essential packages
RUN apk add --no-cache gcc musl-dev

# Set working directory
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=1 GOOS=linux go build -o supervisor-backend ./src/cmd/illa-supervisor-backend
RUN CGO_ENABLED=1 GOOS=linux go build -o supervisor-backend-internal ./src/cmd/illa-supervisor-backend-internal

# Final stage
FROM alpine:latest

# Install necessary runtime packages
RUN apk add --no-cache ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/supervisor-backend .
COPY --from=builder /app/supervisor-backend-internal .
# Expose ports
EXPOSE 8003 9002

# Run the application
COPY scripts/docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]