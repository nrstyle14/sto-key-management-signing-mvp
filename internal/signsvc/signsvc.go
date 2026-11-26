// Package signsvc 는 서명 서버의 트랜잭션 서명 처리(설계서 5.3)다.
//
// M1(T1.5) 구현 범위: 1~4, 7~9단계. 5단계(정책)와 6단계(승인 검증)는 M2(T2.3, T2.4)에서 채운다.
// 그때까지 이 서비스를 여는 HTTP 경로는 통합 시험용 빌드 태그(signtx_m1)로만 등록한다.
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

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/evmtx"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
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
	Intent     json.RawMessage   `json:"intent"`
	IntentHash string            `json:"intent_hash"` // 16진수 64자. 서명 서버는 다시 계산해 대조만 한다
	Approvals  []json.RawMessage `json:"approvals"`   // M2(6단계)에서 검증한다
	UnsignedTx string            `json:"unsigned_tx"` // 0x + type 2 미서명 인코딩(evmtx.EncodeUnsigned)
}

// Response 는 서명 결과다. 같은 request_id 재호출에는 저장된 같은 값을 돌려준다(D-6).
type Response struct {
	RequestID string `json:"request_id"`
	KeyID     string `json:"key_id"`
	Address   string `json:"address"`
	TxHash    string `json:"tx_hash"`
	SignedTx  string `json:"signed_tx"`
}

// Service 는 서명 처리기다.
type Service struct {
	DB      *sql.DB
	Signer  signer.Signer
	Chains  map[string]uint64 // ledger_id → chainId (서명 서버 설정)
	MaxGas  uint64
	Callers []string // 이 처리를 요청할 수 있는 호출자 CN(1단계)
	Now     func() time.Time
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// SignTx 는 설계서 5.3 의 순서대로 검사하고, 하나라도 실패하면 서명하지 않는다.
func (s *Service) SignTx(ctx context.Context, caller string, req Request) (*Response, error) {
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

	// 4. 키: (원장, 기관, 용도)의 ACTIVE 키, 동결 여부
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

	// 5. 정책 평가 — M2(T2.3, T2.4)에서 구현
	// 6. 승인 검증 — M2(T2.2, T2.4)에서 구현

	// 7. 미서명 tx 해석과 intent 대조
	tx, err := evmtx.DecodeUnsigned(rawTx)
	if err != nil {
		return nil, reject(7, evmtx.CodeTxInvalid, "%v", err)
	}
	if err := evmtx.VerifyTx(in, tx, chainID, s.MaxGas); err != nil {
		var ve *evmtx.VerifyError
		if errors.As(err, &ve) {
			return nil, reject(7, ve.Code, "%s", ve.Msg)
		}
		return nil, err
	}

	// 8·9. request_id 예약 → HSM 서명 → 결과 저장을 한 DB 트랜잭션으로 한다.
	return s.signAndStore(ctx, in, h, unsignedHash, key, tx)
}

func (s *Service) signAndStore(ctx context.Context, in *intent.Intent, intentHash, unsignedHash [32]byte, key *keyreg.Key, unsigned *types.Transaction) (*Response, error) {
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
	if _, err := dbtx.ExecContext(ctx, `UPDATE signatures SET tx_hash = ?, signed_tx = ?, signed_at = CURRENT_TIMESTAMP(6) WHERE request_id = ?`,
		txHash[:], raw, in.RequestID); err != nil {
		return nil, reject(9, CodeStoreFailed, "저장: %v", err)
	}
	// TODO(T2.1): 서명 기록과 감사로그 기록을 이 트랜잭션에 함께 넣는다.
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
	err := s.DB.QueryRowContext(ctx, "SELECT s.key_id, k.address, s.unsigned_tx_hash, s.tx_hash, s.signed_tx FROM signatures s JOIN `keys` k ON k.key_id = s.key_id WHERE s.request_id = ?",
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
