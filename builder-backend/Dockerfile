FROM golang:1.20-alpine AS builder

WORKDIR /app
COPY . .

RUN go mod download
RUN go build -o illa-builder-backend ./src/cmd/illa-builder-backend/main.go
RUN go build -o illa-builder-backend-websocket ./src/cmd/illa-builder-backend-websocket/main.go
RUN go build -o illa-builder-backend-internal ./src/cmd/illa-builder-backend-internal/main.go

FROM alpine:latest
WORKDIR /app

RUN apk --no-cache add \
    ca-certificates \
    tzdata \
    curl \
    bash \
    busybox-extras \
    net-tools

COPY --from=builder /app/illa-builder-backend .
COPY --from=builder /app/illa-builder-backend-websocket .
COPY --from=builder /app/illa-builder-backend-internal .

EXPOSE 8001 8002 9001

COPY scripts/docker-entrypoint.sh .
RUN chmod +x docker-entrypoint.sh

ENTRYPOINT ["./docker-entrypoint.sh"]