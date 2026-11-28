# MPC 키 조각 노드 이미지(T5.1, D-25). HSM 라이브러리를 포함하지 않는다.
# 빌드 컨텍스트는 저장소 루트다: docker build -f deploy/mpcd/Dockerfile .
FROM golang:1.27.4-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ENV CGO_ENABLED=0
RUN go build -trimpath -o /out/mpcd ./cmd/mpcd

FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10003 --home-dir /nonexistent --shell /usr/sbin/nologin mpcd \
 && mkdir -p /var/lib/sto/mpc && chown mpcd /var/lib/sto/mpc && chmod 700 /var/lib/sto/mpc
COPY --from=build /out/mpcd /usr/local/bin/mpcd
USER mpcd
ENTRYPOINT ["/usr/local/bin/mpcd"]
