# Fabric 체인코드 이미지(T5.2, 체인코드-as-a-service). 빌드 컨텍스트는 저장소 루트.
FROM golang:1.27.4-trixie AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
ENV CGO_ENABLED=0
RUN go build -trimpath -o /out/sectoken-cc ./cmd/sectoken-cc

FROM debian:trixie-slim
RUN useradd --system --uid 10004 --home-dir /nonexistent --shell /usr/sbin/nologin cc
COPY --from=build /out/sectoken-cc /usr/local/bin/sectoken-cc
USER cc
# 패키지 ID 는 설치 뒤에야 정해지므로 scripts/fabric-up.sh 가 쓴 파일에서 읽는다.
ENTRYPOINT ["sh", "-c", "CHAINCODE_ID=$(cat /fabric/cc-package-id) exec /usr/local/bin/sectoken-cc"]
