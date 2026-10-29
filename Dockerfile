# SPDX-FileCopyrightText: 2026 Anonce Contributors
# SPDX-License-Identifier: AGPL-3.0-only

FROM golang:1.27.3-bookworm@sha256:df4bb0305771186a85d0fd3a40f5c5da9af97ac8053d391ffce2c070817a20c6 AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY migrations/ migrations/
COPY web/ web/
RUN go build -trimpath -buildvcs=false -ldflags="-s -w" -o /out/ ./cmd/server ./cmd/issuer ./cmd/ca ./cmd/probe

FROM build AS migration-build
RUN go build -trimpath -buildvcs=false -ldflags="-s -w" -o /migration/migrate ./cmd/migrate
RUN mkdir /migration/licenses && \
    cp /go/pkg/mod/github.com/jackc/pgx/v5@v5.11.0/LICENSE /migration/licenses/pgx-LICENSE && \
    cp /go/pkg/mod/github.com/jackc/pgpassfile@v1.0.0/LICENSE /migration/licenses/pgpassfile-LICENSE && \
    cp /go/pkg/mod/github.com/jackc/pgservicefile@v0.0.0-20240606120523-5a60cdf6a761/LICENSE /migration/licenses/pgservicefile-LICENSE && \
    cp /go/pkg/mod/github.com/jackc/puddle/v2@v2.2.3/LICENSE /migration/licenses/puddle-LICENSE && \
    cp /go/pkg/mod/github.com/pressly/goose/v3@v3.29.0/LICENSE /migration/licenses/goose-LICENSE && \
    cp /go/pkg/mod/github.com/mfridman/interpolate@v0.0.2/LICENSE.txt /migration/licenses/interpolate-LICENSE && \
    cp /go/pkg/mod/github.com/sethvargo/go-retry@v0.5.0/LICENSE /migration/licenses/go-retry-LICENSE && \
    cp /go/pkg/mod/go.uber.org/multierr@v1.11.0/LICENSE.txt /migration/licenses/multierr-LICENSE && \
    cp /go/pkg/mod/golang.org/x/sync@v0.24.0/LICENSE /migration/licenses/x-sync-LICENSE && \
    cp /go/pkg/mod/golang.org/x/sync@v0.24.0/PATENTS /migration/licenses/x-sync-PATENTS && \
    cp /go/pkg/mod/golang.org/x/text@v0.43.0/LICENSE /migration/licenses/x-text-LICENSE && \
    cp /go/pkg/mod/golang.org/x/text@v0.43.0/PATENTS /migration/licenses/x-text-PATENTS

FROM scratch AS migration
COPY --from=migration-build /migration/migrate /app/migrate
COPY --from=migration-build /migration/licenses/ /licenses/
COPY --from=build /usr/local/go/LICENSE /licenses/Go-LICENSE
COPY --from=build /usr/local/go/PATENTS /licenses/Go-PATENTS
COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE
USER 65532:65532
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/app/migrate"]

FROM build AS account-test
RUN CGO_ENABLED=1 go test -race -c -tags=databaseintegration -o /out/account.test ./internal/identity/accounts && test -x /out/account.test
COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE
USER 65532:65532
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/out/account.test", "-test.run=^TestPostgresAccounts$", "-test.v", "-test.timeout=90s"]

FROM build AS member-backup-test
RUN CGO_ENABLED=1 go test -race -c -tags=databaseintegration -o /out/memberbackup.test ./internal/identity/memberbackup && test -x /out/memberbackup.test
COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE
USER 65532:65532
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/out/memberbackup.test", "-test.run=^TestPostgresMemberBackups$", "-test.v", "-test.timeout=90s"]

FROM build AS submission-record-test
RUN CGO_ENABLED=1 go test -race -c -tags=databaseintegration -o /out/submissionrecords.test ./internal/submission/records && test -x /out/submissionrecords.test
COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE
USER 65532:65532
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
ENTRYPOINT ["/out/submissionrecords.test", "-test.run=^TestPostgresSubmissionRecords$", "-test.v", "-test.timeout=90s"]

FROM scratch AS application
COPY --from=build /out/ /app/
COPY --from=build /usr/local/go/LICENSE /licenses/Go-LICENSE
COPY --from=build /usr/local/go/PATENTS /licenses/Go-PATENTS
COPY LICENSES/AGPL-3.0-only.txt /licenses/anonce-LICENSE
USER 65532:65532
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
CMD ["/app/server"]
