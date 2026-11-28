// mpcd 는 MPC 키 조각 노드다(설계서 6.4 MPC 서명기, D-25). 노드 3개(mpcd-1~3)가 각자 조각을 갖고,
// 서명 서버(CN signerd)만 mTLS 로 호출할 수 있다. 노드끼리는 직접 연결하지 않고 서명 서버가 봉투를 중계한다.
// 이 실행 파일은 internal/hsm 과 원장 RPC 클라이언트를 import 하지 않는다(make lint).
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/config"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/mpcnode"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/server"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/version"
)

// Config 는 mpcd 설정이다. 비밀(신원 키, 저장 키)은 파일 경로로만 받는다.
type Config struct {
	Listen       string             `yaml:"listen"`
	TLS          transport.TLSFiles `yaml:"tls"`
	NodeID       string             `yaml:"node_id"`
	DataDir      string             `yaml:"data_dir"`
	IdentityFile string             `yaml:"identity_file"`  // Ed25519 시드 32바이트(16진수)
	StoreKeyFile string             `yaml:"store_key_file"` // AES-256 키 32바이트(16진수)
	Peers        map[string]string  `yaml:"peers"`          // 노드 ID → 신원 공개키(16진수), 자기 포함 가능
	Coordinator  string             `yaml:"coordinator"`    // 호출을 허용할 인증서 CN(기본 signerd)
}

var nodeRe = regexp.MustCompile(`^mpcd-[1-9]$`)

func loadConfig(path string) (*Config, error) {
	var c Config
	if err := config.Load(path, &c); err != nil {
		return nil, err
	}
	if c.Coordinator == "" {
		c.Coordinator = "signerd"
	}
	var errs []error
	if c.Listen == "" || c.DataDir == "" || c.IdentityFile == "" || c.StoreKeyFile == "" {
		errs = append(errs, errors.New("listen, data_dir, identity_file, store_key_file 이 필요하다"))
	}
	if !nodeRe.MatchString(c.NodeID) {
		errs = append(errs, fmt.Errorf("node_id %q 형식(mpcd-N)", c.NodeID))
	}
	if err := c.TLS.Validate(); err != nil {
		errs = append(errs, err)
	}
	return &c, errors.Join(errs...)
}

func readHexSecret(path string, n int) ([]byte, error) {
	s, err := config.ReadSecret(path)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != n {
		return nil, fmt.Errorf("비밀 파일 %s 형식(16진수 %d바이트)", path, n)
	}
	return b, nil
}

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil)).With("svc", "mpcd")
	var cfgPath string
	root := &cobra.Command{Use: "mpcd", Short: "MPC 키 조각 노드", SilenceUsage: true, SilenceErrors: true}
	root.PersistentFlags().StringVar(&cfgPath, "config", "/etc/sto/mpcd.yaml", "설정 파일")
	root.AddCommand(
		&cobra.Command{Use: "version", Run: func(*cobra.Command, []string) { fmt.Println(version.String("mpcd")) }},
		&cobra.Command{Use: "serve", Short: "노드 실행", RunE: func(cmd *cobra.Command, _ []string) error {
			return serve(cmd.Context(), log, cfgPath)
		}},
		pubkeyCmd(),
		&cobra.Command{Use: "healthcheck", Short: "자기 /healthz 를 mTLS 로 확인(컨테이너 헬스체크용)", RunE: func(cmd *cobra.Command, _ []string) error {
			c, err := loadConfig(cfgPath)
			if err != nil {
				return err
			}
			return server.Probe(cmd.Context(), c.TLS, "localhost", "https://localhost"+c.Listen+"/healthz", nil)
		}},
	)
	if err := root.ExecuteContext(context.Background()); err != nil {
		log.Error("실패", "err", err)
		os.Exit(1)
	}
}

func serve(ctx context.Context, log *slog.Logger, cfgPath string) error {
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		return err
	}
	quietLibraryLog()
	seed, err := readHexSecret(cfg.IdentityFile, ed25519.SeedSize)
	if err != nil {
		return err
	}
	identity := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	storeKey, err := readHexSecret(cfg.StoreKeyFile, 32)
	if err != nil {
		return err
	}
	st, err := mpcnode.NewStore(cfg.DataDir, cfg.NodeID, storeKey)
	clear(storeKey)
	if err != nil {
		return err
	}
	peers := map[string]ed25519.PublicKey{}
	for id, h := range cfg.Peers {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize || !nodeRe.MatchString(id) {
			return fmt.Errorf("peers[%s] 형식", id)
		}
		if id == cfg.NodeID {
			if !identity.Public().(ed25519.PublicKey).Equal(ed25519.PublicKey(b)) {
				return errors.New("peers 의 자기 공개키가 신원 키와 다르다")
			}
			continue
		}
		peers[id] = b
	}
	if len(peers) != 2 {
		return fmt.Errorf("다른 노드 2개의 신원 공개키가 필요하다(받은 수 %d)", len(peers))
	}
	n := mpcnode.New(cfg.NodeID, identity, peers, st)
	tlsCfg, err := transport.ServerTLSConfig(cfg.TLS, []string{cfg.Coordinator, cfg.NodeID})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", transport.RequireCaller([]string{cfg.Coordinator, cfg.NodeID}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		transport.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok", "node": cfg.NodeID})
	})))
	// 노드 API 는 조정자(서명 서버) 인증서만 부를 수 있다.
	mux.Handle("/v1/", transport.RequireCaller([]string{cfg.Coordinator}, mpcnode.Handler(n, log)))
	log.Info("기동", "node", cfg.NodeID, "peers", len(peers))
	return server.Run(ctx, log, cfg.Listen, tlsCfg, mux)
}

// pubkeyCmd 는 신원 키 파일의 공개키(16진수)를 출력한다(설정 생성용, 비밀 값은 출력하지 않는다).
func pubkeyCmd() *cobra.Command {
	var file string
	c := &cobra.Command{Use: "pubkey", Short: "신원 키 파일의 Ed25519 공개키를 출력한다", RunE: func(*cobra.Command, []string) error {
		seed, err := readHexSecret(file, ed25519.SeedSize)
		if err != nil {
			return err
		}
		pub := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
		clear(seed)
		fmt.Println(hex.EncodeToString(pub))
		return nil
	}}
	c.Flags().StringVar(&file, "identity-file", "", "신원 키 파일(16진수 시드 32바이트)")
	_ = c.MarkFlagRequired("identity-file")
	return c
}
