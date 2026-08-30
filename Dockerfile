# syntax=docker/dockerfile:1
ARG GO_VERSION=1.26

FROM golang:${GO_VERSION}-bookworm AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG SERVICE
RUN CGO_ENABLED=0 go build -trimpath -o /out/app ./cmd/${SERVICE}

FROM gcr.io/distroless/static-debian12
COPY --from=builder /out/app /app
ENTRYPOINT ["/app"]
