FROM golang:1.23-alpine AS builder
RUN apk add --no-cache git
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o loganalyzer .

FROM alpine:latest
RUN apk --no-cache add ca-certificates tzdata
WORKDIR /app
COPY --from=builder /app/loganalyzer .
COPY configs/ ./configs/
COPY samples/ ./samples/
RUN mkdir -p /app/reports
ENV TZ=Europe/Istanbul
ENTRYPOINT ["./loganalyzer"]
