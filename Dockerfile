# syntax=docker/dockerfile:1
FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY cmd/ cmd/
COPY internal/ internal/
RUN CGO_ENABLED=0 go build -o /out/server ./cmd/server

FROM alpine:3.20
# ffmpeg: транскодинг видео (transcode.go шеллится в ffmpeg-бинарь)
# ca-certificates: TLS до MinIO/SMTP/внешних API
RUN apk add --no-cache ffmpeg ca-certificates && \
    adduser -D -u 10001 ancen
WORKDIR /app
COPY --from=builder /out/server ./server
COPY web/ web/

USER ancen
EXPOSE 8080
ENTRYPOINT ["./server"]
