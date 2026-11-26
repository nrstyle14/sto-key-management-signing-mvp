# 토큰증권 키 관리·서명 시스템 MVP — 빌드·테스트·환경 명령
SHELL := /bin/bash
GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
PKG := github.com/da-infra/sto-key-management-signing-mvp
LDFLAGS := -X $(PKG)/internal/version.Version=$(VERSION) -X $(PKG)/internal/version.Commit=$(COMMIT)
CMDS := apid signerd stoctl

.PHONY: build test lint test-contracts up down migrate it demo

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
	$(GO) vet -tags integration ./test/...
	./scripts/check-imports.sh

test-contracts: ## 컨트랙트 테스트
	@echo "test-contracts: 아직 구현되지 않았다(T3.1에서 추가)"

COMPOSE := docker compose -f deploy/docker-compose.yml

up: ## 로컬 환경 기동(생성물·비밀 파일이 없으면 먼저 만든다)
	./scripts/gen-besu-network.sh
	./scripts/gen-secrets.sh
	$(COMPOSE) up -d --wait

down: ## 로컬 환경 종료(데이터 볼륨은 남긴다)
	$(COMPOSE) down

migrate: ## DB 마이그레이션과 서버용 계정 권한 부여
	$(GO) run ./scripts/dbmigrate

it: ## 통합 테스트(make up && make migrate 이후)
	$(GO) test -count=1 -tags integration ./test/...

demo: ## 전체 시연
	@echo "demo: 아직 구현되지 않았다(T4.4에서 추가)"
