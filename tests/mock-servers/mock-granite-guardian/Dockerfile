FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY go.mod ./
COPY main.go ./
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o mock-granite-guardian .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/mock-granite-guardian .
EXPOSE 8080
CMD ["./mock-granite-guardian"]
