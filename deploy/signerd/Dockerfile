# 서명 서버 이미지: signerd 와 SoftHSM2(PKCS#11 라이브러리)를 함께 둔다(D-4).
# 토큰 저장소(/var/lib/softhsm/tokens)는 볼륨으로 분리하고 서명 서버만 마운트한다.
# 빌드 컨텍스트는 저장소 루트다: docker build -f deploy/signerd/Dockerfile .
#
# 대상(target)
#   runtime (기본) : signerd 실행 이미지
#   hsmtest        : SoftHSM2 가 든 Go 테스트 이미지(make it 이 HSM 통합 테스트에 쓴다)

FROM golang:1.27.4-trixie AS base
RUN apt-get update \
 && apt-get install -y --no-install-recommends softhsm2 \
 && rm -rf /var/lib/apt/lists/*
COPY deploy/signerd/softhsm2.conf /etc/softhsm/softhsm2.conf
ENV SOFTHSM2_CONF=/etc/softhsm/softhsm2.conf CGO_ENABLED=1

# HSM 통합 테스트용. 소스는 실행 시 /src 로 마운트한다.
FROM base AS hsmtest
WORKDIR /src

FROM base AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY scripts/probe-hsm ./scripts/probe-hsm
# GO_BUILD_TAGS: 통합 시험용 빌드에서만 태그를 준다(예: T1.5 의 signtx_m1). 기본 빌드는 태그가 없다.
ARG GO_BUILD_TAGS=""
RUN go build -trimpath -tags "${GO_BUILD_TAGS}" -o /out/signerd ./cmd/signerd \
 && go build -trimpath -o /out/probe-hsm ./scripts/probe-hsm

FROM debian:trixie-slim AS runtime
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
