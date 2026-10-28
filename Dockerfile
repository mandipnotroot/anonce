# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only

FROM golang:1.27.3-bookworm@sha256:df4bb0305771186a85d0fd3a40f5c5da9af97ac8053d391ffce2c070817a20c6 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY web/ web/
RUN go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/ ./cmd/server ./cmd/issuer ./cmd/ca ./cmd/probe

FROM scratch
COPY --from=build /out/ /app/
COPY --from=build /usr/local/go/LICENSE /licenses/Go-LICENSE
COPY --from=build /usr/local/go/PATENTS /licenses/Go-PATENTS
COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE
USER 65532:65532
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
CMD ["/app/server"]
