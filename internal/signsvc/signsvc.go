// Package signsvc 는 서명 서버의 트랜잭션 서명 처리(설계서 5.3)다.
//
// 1~9단계를 모두 검사한다. 하나라도 실패하면 서명하지 않고, 거부를 사유와 함께 감사로그에 남긴다.
// 검사 단계를 건너뛰는 옵션은 두지 않는다.
package signsvc

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// 거부 코드. 설계서 5.3 의 단계와 1:1 로 대응한다(13절 오류 응답).
const (
	CodeCallerNotAllowed = "SIGN_CALLER_NOT_ALLOWED"    // 1
	CodeRequestConflict  = "SIGN_REQUEST_CONFLICT"      // 2
	CodeIntentInvalid    = "INTENT_INVALID"             // 3
	CodeIntentExpired    = "INTENT_EXPIRED"             // 3
	CodeIntentHash       = "INTENT_HASH_MISMATCH"       // 3
	CodeLedgerUnknown    = "LEDGER_UNKNOWN"             // 3
	CodeKeyNotAvailable  = "KEY_NOT_AVAILABLE"          // 4
	CodeKeyFrozen        = "KEY_FROZEN"                 // 4
	CodeKeyNotSignable   = "KEY_PURPOSE_NOT_SIGNABLE"   // 4 (AUDIT 키는 tx 서명에 쓰지 않는다)
	CodeKeyMismatch      = "KEY_ADDRESS_MISMATCH"       // 4 (업무 서버가 기대한 서명 키가 지금의 ACTIVE 키가 아니다, T3.5)
	CodeApprovalInvalid  = "APPROVAL_INVALID"           // 6 (형식 오류)
	CodeSignFailed       = "HSM_SIGN_FAILED"            // 8
	CodeSigMismatch      = "SIGNATURE_ADDRESS_MISMATCH" // 8
	CodeStoreFailed      = "SIGN_STORE_FAILED"          // 9
)

// Rejection 은 단계별 거부다.
type Rejection struct {
	Step int    `json:"step"`
	Code string `json:"code"`
	Msg  string `json:"message"`
}

func (r *Rejection) Error() string { return fmt.Sprintf("단계 %d %s: %s", r.Step, r.Code, r.Msg) }

func reject(step int, code, format string, a ...any) *Rejection {
	return &Rejection{Step: step, Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Request 는 POST /v1/sign/tx 본문이다.
type Request struct {
	Intent     json.RawMessage     `json:"intent"`
	IntentHash string              `json:"intent_hash"` // 16진수 64자. 서명 서버는 다시 계산해 대조만 한다
	Approvals  []approval.Approval `json:"approvals"`   // 6단계에서 승인자 명부·정책과 대조한다
	UnsignedTx string              `json:"unsigned_tx"` // 0x + type 2 미서명 인코딩(evmtx.EncodeUnsigned)
	// SignerAddress 는 업무 서버가 nonce 를 할당할 때 쓴 서명 키 주소다(선택, 업무 서버는 항상 보낸다).
	// 있으면 4단계에서 (원장, 기관, 용도)의 ACTIVE 키 주소와 같아야 한다. 키 교체·퇴역 뒤에 이전 키 주소로
	// 준비된 요청은 여기서 거부된다(서명 키는 여전히 범위로만 고른다, FR-2.1).
	SignerAddress string `json:"signer_address,omitempty"`
}

// Response 는 서명 결과다. 같은 request_id 재호출에는 저장된 같은 값을 돌려준다(D-6).
type Response struct {
	RequestID string `json:"request_id"`
	KeyID     string `json:"key_id"`
	Address   string `json:"address"`
	TxHash    string `json:"tx_hash"`
	SignedTx  string `json:"signed_tx"`
}

// describeAddress 는 주소에 해당하는 레지스트리 키의 상태를 사유 메시지용으로 돌려준다.
func (s *Service) describeAddress(ctx context.Context, addr string) string {
	var id, status string
	if err := s.DB.QueryRowContext(ctx, "SELECT key_id, status FROM `keys` WHERE address = ?", common.HexToAddress(addr).Hex()).Scan(&id, &status); err != nil {
		return ""
	}
	return fmt.Sprintf(" (그 주소는 %s 키 %s)", status, id)
}

// Service 는 서명 처리기다.
type Service struct {
	DB      *sql.DB
	Signer  signer.Signer
	Chains  map[string]uint64 // ledger_id → chainId (서명 서버 설정)
	MaxGas  uint64
	Callers []string // 이 처리를 요청할 수 있는 호출자 CN(1단계)
	// FabricMSP 는 Fabric 원장 범위 (원장, 기관)의 MSP ID 다(D-26). nil 이면 Fabric 서명을 거부한다.
	FabricMSP func(ledgerID, institutionID string) (string, bool)
	Now       func() time.Time
	// OnAuditError 는 거부 감사 기록이 실패했을 때 부른다(로그용).
	OnAuditError func(error)
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SignTx 는 설계서 5.3 의 순서대로 검사하고, 하나라도 실패하면 서명하지 않는다.
// 거부는 업무 트랜잭션이 롤백된 뒤이므로 별도 트랜잭션으로 감사로그에 남긴다.
func (s *Service) SignTx(ctx context.Context, caller string, req Request) (*Response, error) {
	res, err := s.signTx(ctx, caller, req)
	var rj *Rejection
	if errors.As(err, &rj) {
		s.auditRejection(ctx, caller, req, rj)
	}
	return res, err
}

func (s *Service) auditRejection(ctx context.Context, caller string, req Request, rj *Rejection) {
	p := map[string]any{"step": rj.Step, "code": rj.Code, "reason": truncate(rj.Msg, 300)}
	subject := "-"
	// 거부 사유를 남길 때는 검증되지 않은 intent 에서 식별 필드만 가볍게 읽는다.
	var peek struct {
		RequestID     string `json:"request_id"`
		LedgerID      string `json:"ledger_id"`
		InstitutionID string `json:"institution_id"`
		KeyPurpose    string `json:"key_purpose"`
		DrafterID     string `json:"drafter_id"`
	}
	if json.Unmarshal(req.Intent, &peek) == nil {
		subject = truncate(peek.RequestID, 64)
		p["request_id"], p["ledger_id"], p["institution_id"] = subject, truncate(peek.LedgerID, 64), truncate(peek.InstitutionID, 64)
		p["purpose"], p["drafter_id"] = truncate(peek.KeyPurpose, 32), truncate(peek.DrafterID, 64)
	}
	if _, err := audit.AppendTx(context.WithoutCancel(ctx), s.DB, audit.Entry{Actor: truncate(caller, 64), Action: "SIGN_REJECTED", Subject: subject, Payload: p}); err != nil && s.OnAuditError != nil {
		s.OnAuditError(err)
	}
}

// truncate 는 UTF-8 문자 경계를 지키며 n 바이트 이하로 자른다.
func truncate(v string, n int) string {
	if len(v) <= n {
		return v
	}
	for n > 0 && !utf8.RuneStart(v[n]) {
		n--
	}
	return v[:n]
}

func (s *Service) signTx(ctx context.Context, caller string, req Request) (*Response, error) {
	// 1. 호출자(mTLS 클라이언트 인증서 CN)
	allowed := false
	for _, c := range s.Callers {
		if c == caller {
			allowed = true
		}
	}
	if !allowed {
		return nil, reject(1, CodeCallerNotAllowed, "호출자 %q", caller)
	}

	// 3(앞부분). request_id 를 알기 위해 intent 를 엄격하게 해석한다.
	in, err := intent.Parse(req.Intent)
	if err != nil {
		return nil, reject(3, CodeIntentInvalid, "%v", err)
	}
	rawTx, err := decodeHex(req.UnsignedTx)
	if err != nil {
		return nil, reject(7, evmtx.CodeTxInvalid, "unsigned_tx: %v", err)
	}
	unsignedHash := evmtx.UnsignedHash(rawTx)

	// 2. 이미 서명된 request_id 인가: 같은 미서명 tx 면 저장된 결과, 다르면 거부(D-6)
	if res, err := s.existing(ctx, in.RequestID, unsignedHash); err != nil || res != nil {
		return res, err
	}

	// 3. 만료, intent_hash 재계산·대조, 원장 확인
	if !s.now().Before(in.Expires()) {
		return nil, reject(3, CodeIntentExpired, "expires_at %s", in.ExpiresAt)
	}
	h, err := in.Hash()
	if err != nil {
		return nil, reject(3, CodeIntentInvalid, "%v", err)
	}
	if !strings.EqualFold(req.IntentHash, hex.EncodeToString(h[:])) {
		return nil, reject(3, CodeIntentHash, "intent_hash 가 intent 와 다르다")
	}
	chainID, ok := s.Chains[in.LedgerID]
	if !ok {
		return nil, reject(3, CodeLedgerUnknown, "원장 %q", in.LedgerID)
	}

	// 4. 키: (원장, 기관, 용도)의 ACTIVE 키, 동결 여부. 감사 키는 tx 서명에 쓰지 않는다.
	if in.KeyPurpose == signer.PurposeAudit {
		return nil, reject(4, CodeKeyNotSignable, "AUDIT 키로는 트랜잭션에 서명하지 않는다")
	}
	key, err := keyreg.Lookup(ctx, s.DB, in.LedgerID, in.InstitutionID, in.KeyPurpose)
	if err != nil {
		if errors.Is(err, keyreg.ErrNoActiveKey) || errors.Is(err, keyreg.ErrAmbiguousKey) {
			return nil, reject(4, CodeKeyNotAvailable, "%v", err)
		}
		return nil, err
	}
	if frozen, err := s.frozen(ctx, key); err != nil {
		return nil, err
	} else if frozen != "" {
		return nil, reject(4, CodeKeyFrozen, "동결됨(%s)", frozen)
	}
	if req.SignerAddress != "" && !strings.EqualFold(req.SignerAddress, key.Address.Hex()) {
		return nil, reject(4, CodeKeyMismatch, "요청의 서명 키 %s 는 지금의 ACTIVE 키(%s)가 아니다%s", req.SignerAddress, key.KeyID, s.describeAddress(ctx, req.SignerAddress))
	}

	// 5. 정책: (원장, 기관, 용도)의 ACTIVE 정책 하나로 함수·수량·수신 계좌·가스 상한을 평가한다.
	tx, txErr := evmtx.DecodeUnsigned(rawTx)
	gas := uint64(0)
	if txErr == nil {
		gas = tx.Gas()
	}
	if err := s.checkPolicyAndApprovals(ctx, in, h, req.Approvals, gas); err != nil {
		return nil, err
	}

	// 7. 미서명 tx 해석과 intent 대조
	if txErr != nil {
		return nil, reject(7, evmtx.CodeTxInvalid, "%v", txErr)
	}
	if err := evmtx.VerifyTx(in, tx, chainID, s.MaxGas); err != nil {
		var ve *evmtx.VerifyError
		if errors.As(err, &ve) {
			return nil, reject(7, ve.Code, "%s", ve.Msg)
		}
		return nil, err
	}

	// 8·9. request_id 예약 → HSM 서명 → 결과 저장을 한 DB 트랜잭션으로 한다.
	return s.signAndStore(ctx, caller, in, h, unsignedHash, key, tx)
}

// checkPolicyAndApprovals 는 5단계(정책)와 6단계(승인)다. EVM 서명과 Fabric 서명(D-26)이 같이 쓴다.
func (s *Service) checkPolicyAndApprovals(ctx context.Context, in *intent.Intent, h [32]byte, approvals []approval.Approval, gas uint64) error {
	pol, err := policy.Lookup(ctx, s.DB, in.LedgerID, in.InstitutionID, in.KeyPurpose)
	if err != nil {
		return policyReject(5, err)
	}
	if err := policy.Evaluate(pol, in, gas); err != nil {
		return policyReject(5, err)
	}

	// 6. 승인: 항목 하나라도 잘못되면 요청 전체를 거부한다(중복 승인자, 미등록·비활성, 서명 불일치,
	//    기안자 본인, 다른 기관, 정책 그룹 밖, 반려 포함). 서로 다른 유효 승인자가 M명 이상이어야 한다.
	refs := make([]policy.ApproverRef, 0, len(approvals))
	seen := map[string]bool{}
	for _, a := range approvals {
		if a.ApproverID == "" || !a.Decision.Valid() {
			return reject(6, CodeApprovalInvalid, "승인 항목 형식 오류(approver_id %q, decision %q)", a.ApproverID, a.Decision)
		}
		if seen[a.ApproverID] {
			return reject(6, policy.CodeApprovalDuplicate, "승인자 %s 중복", a.ApproverID)
		}
		seen[a.ApproverID] = true
		ap, err := approval.VerifyOne(ctx, s.DB, a, h)
		if err != nil {
			var ae *approval.Error
			if errors.As(err, &ae) {
				return reject(6, ae.Code, "%s", ae.Error())
			}
			return err
		}
		refs = append(refs, policy.ApproverRef{ApproverID: ap.ApproverID, InstitutionID: ap.InstitutionID, Groups: ap.Groups, Decision: string(a.Decision)})
	}
	if err := policy.CheckApprovals(pol, in.DrafterID, in.InstitutionID, refs); err != nil {
		return policyReject(6, err)
	}
	return nil
}

func (s *Service) signAndStore(ctx context.Context, caller string, in *intent.Intent, intentHash, unsignedHash [32]byte, key *keyreg.Key, unsigned *types.Transaction) (*Response, error) {
	dbtx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, reject(9, CodeStoreFailed, "%v", err)
	}
	defer func() { _ = dbtx.Rollback() }()
	_, err = dbtx.ExecContext(ctx, `INSERT INTO signatures (request_id, key_id, intent_hash, unsigned_tx_hash) VALUES (?, ?, ?, ?)`,
		in.RequestID, key.KeyID, intentHash[:], unsignedHash[:])
	if err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			// 같은 request_id 를 다른 요청이 먼저 커밋했다. 그 결과를 기준으로 2단계를 다시 판단한다.
			_ = dbtx.Rollback()
			res, eerr := s.existing(ctx, in.RequestID, unsignedHash)
			if eerr != nil || res != nil {
				return res, eerr
			}
			return nil, reject(2, CodeRequestConflict, "request_id 예약 충돌")
		}
		return nil, reject(9, CodeStoreFailed, "예약: %v", err)
	}

	digest := evmtx.SigningHash(unsigned)
	r, sv, err := s.Signer.SignDigest(ctx, key.KeyID, digest)
	if err != nil {
		return nil, reject(8, CodeSignFailed, "%v", err)
	}
	sig, err := signer.CompleteEVM(digest, r, sv, key.PublicKey)
	if err != nil {
		return nil, reject(8, CodeSigMismatch, "%v", err)
	}
	signed, raw, err := evmtx.Assemble(unsigned, sig, key.Address)
	if err != nil {
		return nil, reject(8, CodeSigMismatch, "%v", err)
	}
	txHash := signed.Hash()
	if _, err := dbtx.ExecContext(ctx, `UPDATE signatures SET tx_hash = ?, signed_tx = ?, signed_at = CURRENT_TIMESTAMP(6) WHERE request_id = ? AND kind = 'EVM_TX'`,
		txHash[:], raw, in.RequestID); err != nil {
		return nil, reject(9, CodeStoreFailed, "저장: %v", err)
	}
	// 서명 기록과 감사 기록을 같은 트랜잭션으로 저장한다(5.3 의 9단계). 머리 잠금은 마지막에 잡는다.
	if _, err := audit.Append(ctx, dbtx, audit.Entry{Actor: caller, Action: "SIGN_TX", Subject: in.RequestID, Payload: map[string]any{
		"request_id": in.RequestID, "key_id": key.KeyID, "address": key.Address.Hex(), "ledger_id": in.LedgerID,
		"institution_id": in.InstitutionID, "purpose": string(in.KeyPurpose), "intent_hash": hex.EncodeToString(intentHash[:]),
		"unsigned_tx_hash": hex.EncodeToString(unsignedHash[:]), "tx_hash": txHash.Hex(), "drafter_id": in.DrafterID,
		"function": in.Function, "contract": in.Contract, "type": in.Type, "args": in.Args, "code_hash": in.CodeHash,
	}}); err != nil {
		return nil, reject(9, CodeStoreFailed, "감사 기록: %v", err)
	}
	if err := dbtx.Commit(); err != nil {
		return nil, reject(9, CodeStoreFailed, "커밋: %v", err)
	}
	return &Response{RequestID: in.RequestID, KeyID: key.KeyID, Address: key.Address.Hex(),
		TxHash: txHash.Hex(), SignedTx: "0x" + hex.EncodeToString(raw)}, nil
}

// existing 은 커밋된 서명 기록을 본다. 없으면 (nil, nil), 같은 미서명 tx 면 저장된 결과, 다르면 2단계 거부다.
func (s *Service) existing(ctx context.Context, requestID string, unsignedHash [32]byte) (*Response, error) {
	var keyID, addr string
	var storedHash, txHash, signedTx []byte
	err := s.DB.QueryRowContext(ctx, "SELECT s.key_id, k.address, s.unsigned_tx_hash, s.tx_hash, s.signed_tx FROM signatures s JOIN `keys` k ON k.key_id = s.key_id WHERE s.request_id = ? AND s.kind = 'EVM_TX'",
		requestID).Scan(&keyID, &addr, &storedHash, &txHash, &signedTx)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, reject(2, CodeStoreFailed, "서명 기록 조회: %v", err)
	}
	if string(storedHash) != string(unsignedHash[:]) {
		return nil, reject(2, CodeRequestConflict, "request_id %s 는 다른 tx 로 이미 서명됐다", requestID)
	}
	if len(signedTx) == 0 || len(txHash) != 32 {
		return nil, reject(2, CodeRequestConflict, "request_id %s 의 서명 기록이 완전하지 않다", requestID)
	}
	return &Response{RequestID: requestID, KeyID: keyID, Address: addr,
		TxHash: common.BytesToHash(txHash).Hex(), SignedTx: "0x" + hex.EncodeToString(signedTx)}, nil
}

// frozen 은 키·기관·원장 범위의 해제되지 않은 동결이 있으면 그 범위를 돌려준다(설계서 7.3).
func (s *Service) frozen(ctx context.Context, k *keyreg.Key) (string, error) {
	var scope, target string
	err := s.DB.QueryRowContext(ctx, `SELECT scope, target FROM freezes WHERE released_at IS NULL AND
		((scope = 'KEY' AND target = ?) OR (scope = 'INSTITUTION' AND target = ?) OR (scope = 'LEDGER' AND target = ?)) LIMIT 1`,
		k.KeyID, k.InstitutionID, k.LedgerID).Scan(&scope, &target)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("동결 조회: %w", err)
	}
	return scope + ":" + target, nil
}

func policyReject(step int, err error) error {
	var v *policy.Violation
	if errors.As(err, &v) {
		return reject(step, v.Code, "%s", v.Msg)
	}
	return err
}

func decodeHex(s string) ([]byte, error) {
	if !strings.HasPrefix(s, "0x") {
		return nil, errors.New("0x 로 시작하는 16진수여야 한다")
	}
	b, err := hex.DecodeString(s[2:])
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errors.New("비었다")
	}
	return b, nil
}
