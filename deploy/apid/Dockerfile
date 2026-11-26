# 업무 서버 이미지. HSM 라이브러리를 포함하지 않는다(키를 갖지 않는다, FR-1.1).
# 빌드 컨텍스트는 저장소 루트다: docker build -f deploy/apid/Dockerfile .
FROM golang:1.27.4-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ENV CGO_ENABLED=0
RUN go build -trimpath -o /out/apid ./cmd/apid

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10002 --home-dir /nonexistent --shell /usr/sbin/nologin apid
COPY --from=build /out/apid /usr/local/bin/apid
USER apid
ENTRYPOINT ["/usr/local/bin/apid"]
