FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /smtp2m365 ./cmd/smtp2m365

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /smtp2m365 /smtp2m365
# Let's Encrypt account and certificates; mount a persistent volume here.
VOLUME /data
EXPOSE 465 587
ENTRYPOINT ["/smtp2m365"]
CMD ["-config", "/etc/smtp2m365/config.yaml"]
