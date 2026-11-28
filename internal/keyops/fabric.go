package keyops

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Fabric 신원 키 작업(설계서 10.5, D-26). 서명 서버는 CA·원장에 접속하지 않고 HSM 키로 서명하고 결과를 기록만 한다.

// FabricConfig 는 Fabric 원장 설정이다.
type FabricConfig struct {
	// MSP 는 (원장, 기관)의 MSP ID 다. ok 가 false 면 Fabric 범위가 아니다.
	MSP func(ledgerID, institutionID string) (mspID string, ok bool)
	// Roots 는 원장의 MSP 루트 CA 인증서다(발급 인증서·CRL 검증).
	Roots func(ledgerID string) []*x509.Certificate
}

// 재발급 토큰으로 서명할 수 있는 CA 요청(그 밖의 CA 작업은 registrar 가 한다).
const reenrollURI = "/api/v1/reenroll"

// FabricTokenInput 은 FABRIC_TOKEN 의 payload(JSON)다.
type FabricTokenInput struct {
	Method string `json:"method"`
	URI    string `json:"uri"`
	Body   []byte `json:"body"`
}

// p256Signer 는 HSM P-256 키를 crypto.Signer 로 감싼다(low-S, ASN.1 DER).
type p256Signer struct {
	ctx   context.Context
	w     Wrapper
	keyID string
	pub   *ecdsa.PublicKey
}

func (s *p256Signer) Public() crypto.PublicKey { return s.pub }

func (s *p256Signer) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) != 32 {
		return nil, errors.New("keyops: SHA-256 다이제스트만 서명한다")
	}
	var d [32]byte
	copy(d[:], digest)
	r, sv, err := s.w.SignDigest(s.ctx, s.keyID, d)
	if err != nil {
		return nil, err
	}
	sig, err := signer.P256DER(r, sv)
	if err != nil {
		return nil, err
	}
	if !ecdsa.VerifyASN1(s.pub, digest, sig) {
		return nil, errors.New("keyops: HSM 서명이 공개키로 검증되지 않는다")
	}
	return sig, nil
}

func (e *Executor) fabricKey(ctx context.Context, keyID string) (*keyreg.Key, *ecdsa.PublicKey, string, error) {
	k, err := keyreg.Get(ctx, e.DB, keyID)
	if errors.Is(err, keyreg.ErrKeyNotFound) {
		return nil, nil, "", fail(CodeKeyNotFound, "키 %s 가 없다", keyID)
	}
	if err != nil {
		return nil, nil, "", err
	}
	if k.Curve != signer.CurveP256 {
		return nil, nil, "", fail(CodeKeyState, "키 %s 는 Fabric 신원 키(P-256)가 아니다", keyID)
	}
	msp, ok := e.Fabric.MSP(k.LedgerID, k.InstitutionID)
	if !ok {
		return nil, nil, "", fail(CodeKeyState, "(%s, %s) 의 MSP 설정이 없다", k.LedgerID, k.InstitutionID)
	}
	pub, err := signer.P256Public(k.PublicKey)
	if err != nil {
		return nil, nil, "", err
	}
	return k, pub, msp, nil
}

func parseCert(raw []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(raw)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("인증서 PEM 형식")
	}
	return x509.ParseCertificate(b.Bytes)
}

// fabric 은 FABRIC_* 작업을 실행한다.
func (e *Executor) fabric(ctx context.Context, r Request, admins []string) (*Result, error) {
	k, pub, msp, err := e.fabricKey(ctx, r.KeyID)
	if err != nil {
		return nil, err
	}
	res := &Result{OpID: r.OpID, Type: r.Type, KeyID: k.KeyID, Status: string(k.Status)}
	switch r.Type {
	case TypeFabricCSR:
		if k.Status != keyreg.StatusActive && k.Status != keyreg.StatusPending {
			return nil, fail(CodeKeyState, "키 %s 는 %s 다", k.KeyID, k.Status)
		}
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: r.Subject},
			SignatureAlgorithm: x509.ECDSAWithSHA256}, &p256Signer{ctx: ctx, w: e.Wrap, keyID: k.KeyID, pub: pub})
		if err != nil {
			return nil, fail(CodeHSM, "CSR 서명: %v", err)
		}
		res.CSR = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
		return res, e.finish(ctx, r.OpID, audit.Entry{Actor: "signerd", Action: "FABRIC_CSR_SIGNED", Subject: k.KeyID, Payload: map[string]any{
			"request_id": r.OpID, "key_id": k.KeyID, "msp_id": msp, "enrollment_id": r.Subject, "approvers": admins, "reason": r.Reason}})

	case TypeFabricInstallCert:
		cert, err := parseCert(r.Payload)
		if err != nil {
			return nil, fail(CodeInvalid, "%v", err)
		}
		cp, ok := cert.PublicKey.(*ecdsa.PublicKey)
		if !ok || !cp.Equal(pub) {
			return nil, fail(CodeKeyState, "인증서 공개키가 키 %s 와 다르다", k.KeyID)
		}
		roots := e.Fabric.Roots(k.LedgerID)
		if len(roots) == 0 {
			return nil, fail(CodeInvalid, "원장 %s 의 MSP 루트 CA 가 없다", k.LedgerID)
		}
		pool := x509.NewCertPool()
		for _, c := range roots {
			pool.AddCert(c)
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return nil, fail(CodeInvalid, "인증서가 MSP 루트 CA 로 검증되지 않는다: %v", err)
		}
		serial, aki := hex.EncodeToString(cert.SerialNumber.Bytes()), hex.EncodeToString(cert.AuthorityKeyId)
		tx, err := e.DB.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `INSERT INTO fabric_identities (key_id, msp_id, enrollment_id, cert_pem, serial, aki, not_after, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, k.KeyID, msp, cert.Subject.CommonName, string(r.Payload), serial, aki, cert.NotAfter.UTC(), keyreg.IdentityEnrolled); err != nil {
			return nil, fail(CodeKeyState, "키 %s 신원 등록: %v", k.KeyID, err)
		}
		if err := done(ctx, tx, r.OpID); err != nil {
			return nil, err
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "FABRIC_IDENTITY_ENROLLED", Subject: k.KeyID, Payload: map[string]any{
			"request_id": r.OpID, "key_id": k.KeyID, "msp_id": msp, "enrollment_id": cert.Subject.CommonName, "serial": serial, "aki": aki,
			"commitment": r.PayloadSHA256, "approvers": admins, "reason": r.Reason}}); err != nil {
			return nil, err
		}
		res.Serial = serial
		return res, tx.Commit()

	case TypeFabricToken:
		id, err := keyreg.GetIdentity(ctx, e.DB, k.KeyID)
		if err != nil || id.Status != keyreg.IdentityEnrolled {
			return nil, fail(CodeKeyState, "키 %s 에 유효한 신원이 없다", k.KeyID)
		}
		var in FabricTokenInput
		if err := json.Unmarshal(r.Payload, &in); err != nil {
			return nil, fail(CodeInvalid, "토큰 입력: %v", err)
		}
		if in.Method != "POST" || in.URI != reenrollURI {
			return nil, fail(CodeInvalid, "신원 키 토큰은 재발급(POST %s)에만 쓴다", reenrollURI)
		}
		b64 := base64.StdEncoding.EncodeToString
		payload := in.Method + "." + b64([]byte(in.URI)) + "." + b64(in.Body) + "." + b64([]byte(id.CertPEM))
		d := sha256.Sum256([]byte(payload))
		sig, err := (&p256Signer{ctx: ctx, w: e.Wrap, keyID: k.KeyID, pub: pub}).Sign(nil, d[:], crypto.SHA256)
		if err != nil {
			return nil, fail(CodeHSM, "토큰 서명: %v", err)
		}
		res.Token = b64([]byte(id.CertPEM)) + "." + b64(sig)
		return res, e.finish(ctx, r.OpID, audit.Entry{Actor: "signerd", Action: "FABRIC_TOKEN_SIGNED", Subject: k.KeyID, Payload: map[string]any{
			"request_id": r.OpID, "key_id": k.KeyID, "serial": id.Serial, "target": in.URI, "commitment": r.PayloadSHA256, "approvers": admins, "reason": r.Reason}})

	case TypeFabricRevoked:
		id, err := keyreg.GetIdentity(ctx, e.DB, k.KeyID)
		if err != nil {
			return nil, fail(CodeKeyState, "키 %s 에 신원이 없다", k.KeyID)
		}
		if id.Status == keyreg.IdentityRevoked {
			return nil, fail(CodeKeyState, "키 %s 신원은 이미 폐기됐다", k.KeyID)
		}
		b, _ := pem.Decode(r.Payload)
		if b == nil {
			return nil, fail(CodeInvalid, "CRL PEM 형식")
		}
		crl, err := x509.ParseRevocationList(b.Bytes)
		if err != nil {
			return nil, fail(CodeInvalid, "CRL: %v", err)
		}
		// CRL 은 MSP 루트 CA 가 서명한 것이어야 한다.
		verified := false
		for _, root := range e.Fabric.Roots(k.LedgerID) {
			if crl.CheckSignatureFrom(root) == nil {
				verified = true
			}
		}
		if !verified {
			return nil, fail(CodeInvalid, "CRL 이 MSP 루트 CA 서명으로 검증되지 않는다")
		}
		listed := false
		for _, rc := range crl.RevokedCertificateEntries {
			if hex.EncodeToString(rc.SerialNumber.Bytes()) == id.Serial {
				listed = true
			}
		}
		if !listed {
			return nil, fail(CodeInvalid, "CRL 에 키 %s 인증서(일련번호 %s)가 없다", k.KeyID, id.Serial)
		}
		h := sha256.Sum256(r.Payload)
		tx, err := e.DB.BeginTx(ctx, nil)
		if err != nil {
			return nil, err
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `UPDATE fabric_identities SET status = ?, crl_sha256 = ?, revoked_at = CURRENT_TIMESTAMP(6) WHERE key_id = ? AND status = ?`,
			keyreg.IdentityRevoked, h[:], k.KeyID, keyreg.IdentityEnrolled); err != nil {
			return nil, err
		}
		if err := done(ctx, tx, r.OpID); err != nil {
			return nil, err
		}
		if _, err := audit.Append(ctx, tx, audit.Entry{Actor: "signerd", Action: "FABRIC_IDENTITY_REVOKED", Subject: k.KeyID, Payload: map[string]any{
			"request_id": r.OpID, "key_id": k.KeyID, "serial": id.Serial, "commitment": r.PayloadSHA256, "approvers": admins, "reason": r.Reason}}); err != nil {
			return nil, err
		}
		res.Serial = id.Serial
		return res, tx.Commit()
	}
	return nil, fail(CodeInvalid, "알 수 없는 작업 %q", r.Type)
}
