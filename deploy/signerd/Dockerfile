# 서명 서버 이미지: signerd 와 SoftHSM2(PKCS#11 라이브러리)를 함께 둔다(D-4).
# 토큰 저장소(/var/lib/softhsm/tokens)는 볼륨으로 분리하고 서명 서버만 마운트한다.
# 빌드 컨텍스트는 저장소 루트다: docker build -f deploy/signerd/Dockerfile .

FROM golang:1.27.4-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY scripts/probe-hsm ./scripts/probe-hsm
# miekg/pkcs11 은 cgo 로 PKCS#11 라이브러리를 dlopen 한다.
ENV CGO_ENABLED=1
RUN go build -trimpath -o /out/signerd ./cmd/signerd \
 && go build -trimpath -o /out/probe-hsm ./scripts/probe-hsm

FROM debian:trixie-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin signer \
 && usermod -aG softhsm signer \
 && mkdir -p /var/lib/softhsm/tokens \
 && chown -R signer:signer /var/lib/softhsm/tokens \
 && chmod 700 /var/lib/softhsm/tokens
COPY deploy/signerd/softhsm2.conf /etc/softhsm/softhsm2.conf
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf
COPY --from=build /out/signerd /usr/local/bin/signerd
COPY --from=build /out/probe-hsm /usr/local/bin/probe-hsm
VOLUME ["/var/lib/softhsm/tokens"]
USER signer
ENTRYPOINT ["/usr/local/bin/signerd"]
