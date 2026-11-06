# syntax=docker/dockerfile:1

ARG GO_VERSION=1.27
FROM golang:${GO_VERSION}-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/vlanmesh .

FROM alpine:3.22
RUN apk add --no-cache iproute2 ca-certificates tzdata
COPY --from=build /out/vlanmesh /usr/local/bin/vlanmesh

VOLUME ["/data"]
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/vlanmesh"]
CMD ["-config", "/config/config.yaml"]
