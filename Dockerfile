FROM golang:1.21.7-alpine3.19 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./
RUN go build -o /gcp-sakey-generator

FROM alpine:3.18
RUN apk --no-cache add ca-certificates

COPY --from=builder /gcp-sakey-generator ./
RUN chmod +x ./gcp-sakey-generator

ENTRYPOINT ["./gcp-sakey-generator"]
