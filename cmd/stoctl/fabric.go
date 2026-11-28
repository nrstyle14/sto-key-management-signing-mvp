package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/fabricca"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyops"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Fabric 신원 생애주기(설계서 10.5, D-26): stoctl 이 CA(REST)에 접속하고, 서명 서버는 키 작업으로 CSR·토큰 서명과 기록만 한다.

type fabricOpts struct {
	caURL    string
	genDir   string
	secrets  string
	approver approverSet
}

func (o *fabricOpts) flags(c *cobra.Command) {
	c.Flags().StringVar(&o.caURL, "ca", "http://127.0.0.1:7054", "Fabric CA 주소")
	c.Flags().StringVar(&o.genDir, "fabric-dir", "deploy/fabric/generated", "Fabric 생성물 디렉터리(registrar 자격, CRL)")
	c.Flags().StringVar(&o.secrets, "secrets-dir", "deploy/secrets", "비밀 디렉터리(registrar 비밀번호)")
	o.approver.flags(c)
}

type fabricIdentity struct {
	KeyID        string `json:"key_id"`
	MSPID        string `json:"msp_id"`
	EnrollmentID string `json:"enrollment_id"`
	CertPEM      string `json:"cert_pem"`
	Serial       string `json:"serial"`
	AKI          string `json:"aki"`
	Status       string `json:"status"`
}

func (g *globals) fabricIdentities(cmd *cobra.Command) ([]fabricIdentity, error) {
	cl, err := g.client(g.signerURL)
	if err != nil {
		return nil, err
	}
	var out struct {
		Identities []fabricIdentity `json:"identities"`
	}
	return out.Identities, cl.do(cmd.Context(), "GET", "/v1/fabric/identities", nil, &out)
}

// registrar 는 registrar 자격(소프트웨어 키, 파일)이다. 없으면 Basic 인증으로 enroll 해 만든다.
// 저장된 자격은 CA 에 조회해 확인한다. CA 데이터가 새로 만들어졌으면(볼륨 삭제) CA 가 그 인증서를 몰라 401 이므로
// 다시 enroll 한다.
func (o *fabricOpts) registrar(ca *fabricca.Client) (*ecdsa.PrivateKey, []byte, error) {
	dir := filepath.Join(o.genDir, "registrar")
	keyFile, certFile := filepath.Join(dir, "key.pem"), filepath.Join(dir, "cert.pem")
	if kb, err := os.ReadFile(keyFile); err == nil {
		cb, err := os.ReadFile(certFile)
		if err != nil {
			return nil, nil, err
		}
		b, _ := pem.Decode(kb)
		if b == nil {
			return nil, nil, errors.New("registrar 키 형식")
		}
		k, err := x509.ParseECPrivateKey(b.Bytes)
		if err != nil {
			return nil, nil, err
		}
		_, err = ca.Do("GET", "/api/v1/identities/registrar", nil, fabricca.SoftwareToken(k, cb))
		var he *fabricca.HTTPError
		if err == nil {
			return k, cb, nil
		}
		if !errors.As(err, &he) || he.Status != http.StatusUnauthorized {
			return nil, nil, err
		}
		fmt.Fprintln(os.Stderr, "registrar 자격을 CA 가 모른다(CA 데이터 재생성). 다시 발급한다")
	}
	pw, err := os.ReadFile(filepath.Join(o.secrets, "fabric_ca_registrar_password"))
	if err != nil {
		return nil, nil, fmt.Errorf("registrar 비밀번호: %w", err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csr, err := fabricca.SoftwareCSR(k, "registrar")
	if err != nil {
		return nil, nil, err
	}
	res, err := ca.Do("POST", "/api/v1/enroll", fabricca.EnrollBody(csr), fabricca.Basic("registrar", strings.TrimSpace(string(pw))))
	if err != nil {
		return nil, nil, err
	}
	cert, err := fabricca.CertFrom(res)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	der, _ := x509.MarshalECPrivateKey(k)
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		return nil, nil, err
	}
	return k, cert, os.WriteFile(certFile, cert, 0o600)
}

func payloadOp(t keyops.Type, keyID, reason string, payload []byte) keyops.Request {
	r := keyops.New(t, time.Now())
	h := sha256.Sum256(payload)
	r.KeyID, r.Reason, r.Payload, r.PayloadSHA256 = keyID, reason, payload, hex.EncodeToString(h[:])
	return r
}

// enrollKey 는 키를 CA 에 등록·발급하고 서명 서버에 인증서를 등록한다(FABRIC_CSR → enroll → FABRIC_INSTALL_CERT).
func (g *globals) enrollKey(cmd *cobra.Command, o *fabricOpts, keyID, enrollmentID string) (string, error) {
	ca := fabricca.New(o.caURL)
	rk, rc, err := o.registrar(ca)
	if err != nil {
		return "", err
	}
	secretB := make([]byte, 16)
	_, _ = rand.Read(secretB)
	secret := hex.EncodeToString(secretB) // 일회용 등록 비밀(출력하지 않는다)
	body, _ := json.Marshal(map[string]any{"id": enrollmentID, "type": "client", "secret": secret, "affiliation": "", "max_enrollments": -1})
	if _, err := ca.Do("POST", "/api/v1/register", body, fabricca.SoftwareToken(rk, rc)); err != nil {
		return "", err
	}
	r := keyops.New(keyops.TypeFabricCSR, time.Now())
	r.KeyID, r.Subject, r.Reason = keyID, enrollmentID, "Fabric 신원 발급"
	res, err := g.keyOp(cmd.Context(), r, &o.approver)
	if err != nil {
		return "", err
	}
	out, err := ca.Do("POST", "/api/v1/enroll", fabricca.EnrollBody(res.CSR), fabricca.Basic(enrollmentID, secret))
	if err != nil {
		return "", err
	}
	cert, err := fabricca.CertFrom(out)
	if err != nil {
		return "", err
	}
	ins, err := g.keyOp(cmd.Context(), payloadOp(keyops.TypeFabricInstallCert, keyID, "Fabric 인증서 등록", cert), &o.approver)
	if err != nil {
		return "", err
	}
	return ins.Serial, nil
}

func fabricCmd(g *globals) *cobra.Command {
	c := &cobra.Command{Use: "fabric", Short: "Fabric 신원 발급·재발급·폐기(설계서 10.5, D-26)"}

	var o fabricOpts
	var keyID, enrollmentID string
	enroll := &cobra.Command{
		Use:   "enroll",
		Short: "Fabric 신원 키(P-256)를 CA 에 등록·발급하고 인증서를 서명 서버에 등록한다(보안관리자 2명)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if enrollmentID == "" {
				enrollmentID = keyID
			}
			serial, err := g.enrollKey(cmd, &o, keyID, enrollmentID)
			if err != nil {
				return err
			}
			return printJSON(map[string]string{"key_id": keyID, "enrollment_id": enrollmentID, "serial": serial, "status": "ENROLLED"})
		},
	}
	enroll.Flags().StringVar(&keyID, "key", "", "Fabric 신원 키 ID")
	enroll.Flags().StringVar(&enrollmentID, "enrollment-id", "", "CA 등록 ID(비우면 키 ID)")
	_ = enroll.MarkFlagRequired("key")
	o.flags(enroll)

	var ro fabricOpts
	var oldKey string
	reenroll := &cobra.Command{
		Use:   "reenroll",
		Short: "재발급: 새 키 생성 → 새 키 CSR·이전 인증서 토큰으로 reenroll → 새 인증서 등록 → 이전 키 퇴역(새 키 활성화)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			ids, err := g.fabricIdentities(cmd)
			if err != nil {
				return err
			}
			var old *fabricIdentity
			for i := range ids {
				if ids[i].KeyID == oldKey && ids[i].Status == "ENROLLED" {
					old = &ids[i]
				}
			}
			if old == nil {
				return fmt.Errorf("키 %s 에 유효한 신원이 없다", oldKey)
			}
			k, err := g.keyByID(ctx, oldKey)
			if err != nil {
				return err
			}
			// 1. 새 키(PENDING, 교체 대상 = 이전 키)
			gr := keyops.New(keyops.TypeGenerate, time.Now())
			gr.LedgerID, gr.InstitutionID, gr.Purpose, gr.KeyID, gr.RotatedFrom, gr.Reason = k.LedgerID, k.InstitutionID, signer.Purpose(k.Purpose),
				newKeyID(k.InstitutionID, signer.Purpose(k.Purpose)), oldKey, "Fabric 신원 재발급"
			gen, err := g.keyOp(ctx, gr, &ro.approver)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "1. 새 키 %s %s\n", gen.KeyID, gen.Status)
			// 2. 새 키 CSR(같은 enrollment ID)
			cr := keyops.New(keyops.TypeFabricCSR, time.Now())
			cr.KeyID, cr.Subject, cr.Reason = gen.KeyID, old.EnrollmentID, "Fabric 신원 재발급"
			csr, err := g.keyOp(ctx, cr, &ro.approver)
			if err != nil {
				return err
			}
			// 3. 이전 키로 reenroll 토큰(본문이 서명 대상에 묶인다)
			body := fabricca.EnrollBody(csr.CSR)
			in, _ := json.Marshal(keyops.FabricTokenInput{Method: "POST", URI: "/api/v1/reenroll", Body: body})
			tok, err := g.keyOp(ctx, payloadOp(keyops.TypeFabricToken, oldKey, "Fabric 신원 재발급", in), &ro.approver)
			if err != nil {
				return err
			}
			ca := fabricca.New(ro.caURL)
			out, err := ca.Do("POST", "/api/v1/reenroll", body, fabricca.FixedToken(tok.Token))
			if err != nil {
				return err
			}
			cert, err := fabricca.CertFrom(out)
			if err != nil {
				return err
			}
			fmt.Fprintln(os.Stderr, "2. CA 재발급(이전 인증서 토큰, 새 키 CSR)")
			// 4. 새 인증서 등록 → 이전 키 퇴역·새 키 활성화
			ins, err := g.keyOp(ctx, payloadOp(keyops.TypeFabricInstallCert, gen.KeyID, "Fabric 신원 재발급", cert), &ro.approver)
			if err != nil {
				return err
			}
			rt := keyops.New(keyops.TypeRetire, time.Now())
			rt.KeyID, rt.Successor, rt.Reason = oldKey, gen.KeyID, "Fabric 신원 재발급"
			ret, err := g.keyOp(ctx, rt, &ro.approver)
			if err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "3. 새 인증서 %s 등록, 이전 키 %s, 새 키 %s ACTIVE\n", ins.Serial, ret.Status, ret.Activate)
			fmt.Fprintln(os.Stderr, "   이전 인증서는 폐기 전까지 유효하다: stoctl fabric revoke --key", oldKey)
			return printJSON(map[string]string{"old_key": oldKey, "new_key": gen.KeyID, "serial": ins.Serial})
		},
	}
	reenroll.Flags().StringVar(&oldKey, "key", "", "재발급할(이전) 신원 키 ID")
	_ = reenroll.MarkFlagRequired("key")
	ro.flags(reenroll)

	var vo fabricOpts
	var revKey, reason string
	var skipChannel bool
	revoke := &cobra.Command{
		Use:   "revoke",
		Short: "폐기: CA revoke+gencrl(registrar) → 채널 설정 revocation_list 갱신(기관 관리자) → 서명 서버 기록",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := g.fabricIdentities(cmd)
			if err != nil {
				return err
			}
			var id *fabricIdentity
			for i := range ids {
				if ids[i].KeyID == revKey {
					id = &ids[i]
				}
			}
			if id == nil {
				return fmt.Errorf("키 %s 에 신원이 없다", revKey)
			}
			ca := fabricca.New(vo.caURL)
			rk, rc, err := vo.registrar(ca)
			if err != nil {
				return err
			}
			// 이미 CA 에서 폐기됐으면(앞선 시도가 중간에 멈춤) 다시 폐기하지 않고 CRL 만 받아 이어 간다.
			crl, listed, err := currentCRL(ca, rk, rc, id.Serial)
			if err != nil {
				return err
			}
			if !listed {
				body, _ := json.Marshal(map[string]any{"serial": id.Serial, "aki": id.AKI, "reason": reason, "gencrl": true})
				out, err := ca.Do("POST", "/api/v1/revoke", body, fabricca.SoftwareToken(rk, rc))
				if err != nil {
					return err
				}
				if crl, err = fabricca.CRLFrom(out); err != nil {
					return err
				}
			} else {
				fmt.Fprintln(os.Stderr, "   CA 에서 이미 폐기됐다: 현재 CRL 로 이어 간다")
			}
			dir := filepath.Join(vo.genDir, "crl")
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return err
			}
			crlFile := filepath.Join(dir, id.Serial+".pem")
			if err := os.WriteFile(crlFile, crl, 0o644); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "1. CA 폐기·CRL(%d바이트) %s\n", len(crl), crlFile)
			if !skipChannel {
				sh := exec.CommandContext(cmd.Context(), "scripts/fabric-crl-update.sh", crlFile)
				sh.Stdout, sh.Stderr = os.Stderr, os.Stderr
				if err := sh.Run(); err != nil {
					return fmt.Errorf("채널 설정 갱신: %w", err)
				}
				fmt.Fprintln(os.Stderr, "2. 채널 설정 revocation_list 갱신(기관 관리자 서명)")
			}
			res, err := g.keyOp(cmd.Context(), payloadOp(keyops.TypeFabricRevoked, revKey, "Fabric 신원 폐기: "+reason, crl), &vo.approver)
			if err != nil {
				return err
			}
			return printJSON(map[string]string{"key_id": revKey, "serial": res.Serial, "status": "REVOKED", "crl": crlFile})
		},
	}
	revoke.Flags().StringVar(&revKey, "key", "", "폐기할 신원 키 ID")
	revoke.Flags().StringVar(&reason, "reason", "keycompromise", "폐기 사유(CA reason: keycompromise, superseded 등)")
	revoke.Flags().BoolVar(&skipChannel, "skip-channel-update", false, "채널 설정 갱신을 건너뛴다(시험용: 이 경우 폐기는 원장에서 효력이 없다)")
	_ = revoke.MarkFlagRequired("key")
	vo.flags(revoke)

	list := &cobra.Command{
		Use: "list", Short: "Fabric 신원(키, MSP, enrollment ID, 일련번호, 상태)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ids, err := g.fabricIdentities(cmd)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			for _, i := range ids {
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", i.KeyID, i.MSPID, i.EnrollmentID, i.Serial, i.Status)
			}
			return tw.Flush()
		},
	}
	c.AddCommand(enroll, reenroll, revoke, list)
	return c
}

// currentCRL 은 CA 의 현재 CRL 과 serial 이 이미 들어 있는지다(registrar 토큰).
func currentCRL(ca *fabricca.Client, rk *ecdsa.PrivateKey, rc []byte, serial string) ([]byte, bool, error) {
	out, err := ca.Do("POST", "/api/v1/gencrl", []byte("{}"), fabricca.SoftwareToken(rk, rc))
	if err != nil {
		return nil, false, err
	}
	crl, err := fabricca.CRLFrom(out)
	if err != nil {
		return nil, false, err
	}
	b, _ := pem.Decode(crl)
	if b == nil {
		return crl, false, nil
	}
	list, err := x509.ParseRevocationList(b.Bytes)
	if err != nil {
		return nil, false, err
	}
	for _, e := range list.RevokedCertificateEntries {
		if hex.EncodeToString(e.SerialNumber.Bytes()) == serial {
			return crl, true, nil
		}
	}
	return crl, false, nil
}
