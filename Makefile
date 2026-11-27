# 토큰증권 키 관리·서명 시스템 MVP — 빌드·테스트·환경 명령
SHELL := /bin/bash
GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG := github.com/da-infra/sto-key-management-signing-mvp
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)
CMDS := apid signerd stoctl

.PHONY: build test lint gen test-contracts up down migrate it demo

build: ## 세 실행 파일 빌드
	@mkdir -p bin
	@for c in $(CMDS); do \
		echo "build $$c"; \
		$(GO) build -ldflags "$(LDFLAGS)" -o bin/$$c ./cmd/$$c || exit 1; \
	done

test: ## 단위 테스트
	$(GO) test ./...

lint: ## 정적 검사와 import 경계 검사
	@out="$$(gofmt -l cmd internal scripts test)"; if [ -n "$$out" ]; then echo "gofmt 필요:"; echo "$$out"; exit 1; fi
	$(GO) vet ./...
	$(GO) vet -tags integration ./...
	./scripts/check-imports.sh

gen: ## 컨트랙트 컴파일과 Go 바인딩 생성(abigen)
	./scripts/gen-bindings.sh

test-contracts: ## 컨트랙트 테스트(Foundry)와 커밋된 바인딩이 소스와 같은지 확인
	cd contracts && forge test
	./scripts/gen-bindings.sh --check

COMPOSE := docker compose -f deploy/docker-compose.yml

INFRA := mysql besu-node1 besu-node2 besu-node3 besu-node4

up: ## 로컬 환경 기동: 생성물·비밀·승인자 키 → 인프라 → 마이그레이션 → 토큰·부트스트랩 → signerd, apid
	./scripts/gen-besu-network.sh
	./scripts/gen-secrets.sh
	./scripts/gen-certs.sh
	./scripts/gen-approvers.sh
	$(COMPOSE) up -d --wait $(INFRA)
	$(MAKE) --no-print-directory migrate
	./scripts/init-signer.sh
	$(COMPOSE) up -d --wait --build signerd apid

down: ## 로컬 환경 종료(데이터 볼륨은 남긴다)
	$(COMPOSE) down

migrate: ## DB 마이그레이션과 서버용 계정 권한 부여
	$(GO) run ./scripts/dbmigrate

# 호스트에서 실행하는 통합 테스트 패키지(HSM 이 필요한 패키지는 scripts/it-hsm.sh 가 컨테이너에서 실행).
# -p 1: 서버를 내렸다 올리는 test/ 와 레지스트리에 시험 키를 잠시 넣는 패키지가 겹치지 않게 한 패키지씩 실행한다.
HOST_IT_PKGS := ./test/... ./internal/audit/... ./internal/approval/... ./internal/keyreg/... ./internal/signsvc/... ./internal/workflow/... ./internal/freeze/... ./internal/alarm/... ./internal/ledger/... ./internal/registry/... ./internal/keyops/...

it: ## 통합 테스트(make up 이후): 호스트 DB·서버·종단 시험 → SoftHSM2 컨테이너 시험
	$(GO) test -count=1 -p 1 -tags integration $(HOST_IT_PKGS)
	./scripts/it-hsm.sh

demo: ## 전체 시연
	@echo "demo: 아직 구현되지 않았다(T4.4에서 추가)"
