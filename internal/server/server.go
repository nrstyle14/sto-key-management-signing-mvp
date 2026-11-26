// Package server 는 apid, signerd 가 공유하는 mTLS HTTP 서버 실행과 헬스체크 호출을 제공한다.
package server

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// Run 은 mTLS 서버를 띄우고 SIGINT/SIGTERM 에 정상 종료한다.
func Run(ctx context.Context, log *slog.Logger, addr string, tlsCfg *tls.Config, h http.Handler) error {
	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	srv := &http.Server{
		Addr:              addr,
		Handler:           h,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("리슨(%s): %w", addr, err)
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ServeTLS(ln, "", "") }()
	log.Info("서버 시작", "addr", addr)
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Info("서버 종료 중")
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return srv.Shutdown(sctx)
	}
}

// Probe 는 mTLS 로 url 의 /healthz 를 호출해 200 이면 nil 을 돌려준다. 응답 본문을 out 에 해석한다.
func Probe(ctx context.Context, files transport.TLSFiles, serverName, url string, out any) error {
	cfg, err := transport.ClientTLSConfig(files, serverName)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := transport.NewClient(cfg, 5*time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("헬스 응답 해석: %w", err)
		}
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("헬스 상태 %d", resp.StatusCode)
	}
	return nil
}
