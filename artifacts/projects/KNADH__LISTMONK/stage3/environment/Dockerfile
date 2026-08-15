FROM golang:1.26-alpine AS builder

ARG SOURCE_COMMIT
ARG STUDY_VERSION
RUN apk add --no-cache git make nodejs npm yarn
WORKDIR /src
COPY . .
RUN touch frontend/.gitignore
RUN make dist \
    LAST_COMMIT=${SOURCE_COMMIT} \
    LISTMONK_VERSION=${STUDY_VERSION} \
    STUFFBIN=/go/bin/stuffbin \
    YARN=yarn

FROM alpine:3.23
RUN apk add --no-cache ca-certificates shadow su-exec tzdata
WORKDIR /listmonk
COPY --from=builder /src/listmonk ./listmonk
COPY --from=builder /src/config.toml.sample ./config.toml
COPY --from=builder /src/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
EXPOSE 9000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["./listmonk"]
