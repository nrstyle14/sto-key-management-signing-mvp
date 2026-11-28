package signsvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/go-sql-driver/mysql"
	"github.com/hyperledger/fabric-protos-go-apiv2/common"
	"github.com/hyperledger/fabric-protos-go-apiv2/gateway"
	"github.com/hyperledger/fabric-protos-go-apiv2/msp"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"
	"google.golang.org/protobuf/proto"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/intent"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/keyreg"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signer"
)

// Fabric 서명(설계서 10.5, D-26). 서명 서버는 다이제스트가 아니라 원문을 받아 해석하고 승인된 intent 와 대조한다.
// 요청 하나에 종류별(PROPOSAL, TRANSACTION, COMMIT) 서명 1회이고, 같은 원문 재요청에는 저장된 서명을 돌려준다.

// Fabric 서명 종류
const (
	KindProposal    = "PROPOSAL"
	KindTransaction = "TRANSACTION"
	KindCommit      = "COMMIT"
)

// Fabric 7단계 거부 코드
const (
	CodeFabricInvalid       = "FABRIC_PAYLOAD_INVALID"
	CodeFabricMismatch      = "FABRIC_PAYLOAD_MISMATCH"
	CodeFabricNoProposal    = "FABRIC_PROPOSAL_NOT_SIGNED"
	CodeFabricIdentity      = "FABRIC_IDENTITY_NOT_AVAILABLE" // 4: 신원 인증서 없음·폐기
	CodeFabricNotFabricType = "FABRIC_INTENT_TYPE"
)

// FabricRequest 는 POST /v1/sign/fabric 요청이다.
type FabricRequest struct {
	Intent     json.RawMessage     `json:"intent"`
	IntentHash string              `json:"intent_hash"`
	Approvals  []approval.Approval `json:"approvals"`
	Kind       string              `json:"kind"`
	Payload    []byte              `json:"payload"` // ProposedTransaction, PreparedTransaction, SignedCommitStatusRequest 의 protobuf
}

// FabricResponse 는 서명 결과다. Signature 는 low-S ASN.1 DER 이다.
type FabricResponse struct {
	RequestID string `json:"request_id"`
	KeyID     string `json:"key_id"`
	Kind      string `json:"kind"`
	TxID      string `json:"tx_id"`
	Signature []byte `json:"signature"`
}

// SignFabric 은 Fabric 원문 서명이다. 거부는 감사로그(SIGN_REJECTED)에 남는다.
func (s *Service) SignFabric(ctx context.Context, caller string, req FabricRequest) (*FabricResponse, error) {
	res, err := s.signFabric(ctx, caller, req)
	var rj *Rejection
	if errors.As(err, &rj) {
		s.auditRejection(ctx, caller, Request{Intent: req.Intent}, rj)
	}
	return res, err
}

type parsedProposal struct {
	txID     string
	channel  string
	chHdr    []byte // ChannelHeader 원문
	sigHdr   []byte // SignatureHeader 원문
	payload  []byte // Proposal.Payload 원문(ChaincodeProposalPayload, transient 없음)
	creator  []byte // SerializedIdentity 원문
	propByte []byte // ProposalBytes
}

func fabricReject(code, format string, a ...any) error { return reject(7, code, format, a...) }

func parseProposalBytes(pb []byte) (*parsedProposal, *peer.ChaincodeInvocationSpec, *msp.SerializedIdentity, string, error) {
	var prop peer.Proposal
	if err := proto.Unmarshal(pb, &prop); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "Proposal: %v", err)
	}
	var hdr common.Header
	if err := proto.Unmarshal(prop.Header, &hdr); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "Header: %v", err)
	}
	var ch common.ChannelHeader
	if err := proto.Unmarshal(hdr.ChannelHeader, &ch); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "ChannelHeader: %v", err)
	}
	var sh common.SignatureHeader
	if err := proto.Unmarshal(hdr.SignatureHeader, &sh); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "SignatureHeader: %v", err)
	}
	var creator msp.SerializedIdentity
	if err := proto.Unmarshal(sh.Creator, &creator); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "creator: %v", err)
	}
	var ext peer.ChaincodeHeaderExtension
	if err := proto.Unmarshal(ch.Extension, &ext); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "ChaincodeHeaderExtension: %v", err)
	}
	var cpp peer.ChaincodeProposalPayload
	if err := proto.Unmarshal(prop.Payload, &cpp); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "ChaincodeProposalPayload: %v", err)
	}
	if len(cpp.TransientMap) != 0 {
		return nil, nil, nil, "", fabricReject(CodeFabricMismatch, "transient 데이터는 쓰지 않는다")
	}
	var cis peer.ChaincodeInvocationSpec
	if err := proto.Unmarshal(cpp.Input, &cis); err != nil {
		return nil, nil, nil, "", fabricReject(CodeFabricInvalid, "ChaincodeInvocationSpec: %v", err)
	}
	if common.HeaderType(ch.Type) != common.HeaderType_ENDORSER_TRANSACTION {
		return nil, nil, nil, "", fabricReject(CodeFabricMismatch, "제안 유형 %v", common.HeaderType(ch.Type))
	}
	// txID = hex(SHA-256(nonce ‖ creator))
	h := sha256.Sum256(append(append([]byte{}, sh.Nonce...), sh.Creator...))
	if len(sh.Nonce) < 16 || ch.TxId != hex.EncodeToString(h[:]) {
		return nil, nil, nil, "", fabricReject(CodeFabricMismatch, "txID 가 nonce·생성자에서 계산한 값과 다르다")
	}
	if cis.ChaincodeSpec == nil || cis.ChaincodeSpec.ChaincodeId == nil || ext.ChaincodeId == nil ||
		cis.ChaincodeSpec.ChaincodeId.Name != ext.ChaincodeId.Name {
		return nil, nil, nil, "", fabricReject(CodeFabricMismatch, "체인코드 이름이 헤더와 입력에서 다르다")
	}
	return &parsedProposal{txID: ch.TxId, channel: ch.ChannelId, chHdr: hdr.ChannelHeader, sigHdr: hdr.SignatureHeader, payload: prop.Payload,
		creator: sh.Creator, propByte: pb}, &cis, &creator, ext.ChaincodeId.Name, nil
}

func (s *Service) signFabric(ctx context.Context, caller string, req FabricRequest) (*FabricResponse, error) {
	// 1. 호출자
	allowed := false
	for _, c := range s.Callers {
		if c == caller {
			allowed = true
		}
	}
	if !allowed {
		return nil, reject(1, CodeCallerNotAllowed, "호출자 %q", caller)
	}
	in, err := intent.Parse(req.Intent)
	if err != nil {
		return nil, reject(3, CodeIntentInvalid, "%v", err)
	}
	if in.Type != intent.TypeFabricTX {
		return nil, reject(3, CodeFabricNotFabricType, "Fabric 서명은 FABRIC_TX intent 만 받는다(%s)", in.Type)
	}
	switch req.Kind {
	case KindProposal, KindTransaction, KindCommit:
	default:
		return nil, reject(7, CodeFabricInvalid, "알 수 없는 서명 종류 %q", req.Kind)
	}
	if len(req.Payload) == 0 || len(req.Payload) > 4<<20 {
		return nil, reject(7, CodeFabricInvalid, "payload 크기")
	}
	payloadHash := sha256.Sum256(req.Payload)

	// 2. (request_id, kind) 이미 서명됐는가: 같은 원문이면 저장된 서명, 다르면 거부
	if res, err := s.existingFabric(ctx, in.RequestID, req.Kind, payloadHash); err != nil || res != nil {
		return res, err
	}

	// 3. 만료, intent_hash, 원장
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
	if s.FabricMSP == nil {
		return nil, reject(3, CodeLedgerUnknown, "이 서명 서버는 Fabric 원장을 모른다")
	}
	mspID, ok := s.FabricMSP(in.LedgerID, in.InstitutionID)
	if !ok {
		return nil, reject(3, CodeLedgerUnknown, "Fabric 원장 범위 (%s, %s) 가 없다", in.LedgerID, in.InstitutionID)
	}

	// 4. 키·동결·신원
	if in.KeyPurpose == signer.PurposeAudit {
		return nil, reject(4, CodeKeyNotSignable, "AUDIT 키로는 서명하지 않는다")
	}
	key, err := keyreg.Lookup(ctx, s.DB, in.LedgerID, in.InstitutionID, in.KeyPurpose)
	if err != nil {
		if errors.Is(err, keyreg.ErrNoActiveKey) || errors.Is(err, keyreg.ErrAmbiguousKey) {
			return nil, reject(4, CodeKeyNotAvailable, "%v", err)
		}
		return nil, err
	}
	if key.Curve != signer.CurveP256 {
		return nil, reject(4, CodeKeyNotAvailable, "키 %s 는 Fabric 신원 키(P-256)가 아니다", key.KeyID)
	}
	if frozen, err := s.frozen(ctx, key); err != nil {
		return nil, err
	} else if frozen != "" {
		return nil, reject(4, CodeKeyFrozen, "동결됨(%s)", frozen)
	}
	id, err := keyreg.GetIdentity(ctx, s.DB, key.KeyID)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && id.Status != keyreg.IdentityEnrolled) {
		return nil, reject(4, CodeFabricIdentity, "키 %s 에 유효한 신원 인증서가 없다", key.KeyID)
	}
	if err != nil {
		return nil, err
	}
	if id.MSPID != mspID {
		return nil, reject(4, CodeFabricIdentity, "신원 MSP %s 가 설정 %s 와 다르다", id.MSPID, mspID)
	}

	// 5·6. 정책과 승인(EVM 서명과 같은 검사)
	if err := s.checkPolicyAndApprovals(ctx, in, h, req.Approvals, 0); err != nil {
		return nil, err
	}

	// 7. 원문 해석과 대조
	channel, chaincode := in.FabricTarget()
	var digest [32]byte
	var txID string
	var keep []byte
	switch req.Kind {
	case KindProposal:
		var pt gateway.ProposedTransaction
		if err := proto.Unmarshal(req.Payload, &pt); err != nil || pt.Proposal == nil {
			return nil, fabricReject(CodeFabricInvalid, "ProposedTransaction")
		}
		pp, cis, creator, cc, err := parseProposalBytes(pt.Proposal.ProposalBytes)
		if err != nil {
			return nil, err
		}
		if pt.TransactionId != pp.txID {
			return nil, fabricReject(CodeFabricMismatch, "transaction_id 가 헤더와 다르다")
		}
		if pp.channel != channel || cc != chaincode {
			return nil, fabricReject(CodeFabricMismatch, "채널·체인코드 %s/%s 가 intent %s 와 다르다", pp.channel, cc, in.Contract)
		}
		args := cis.ChaincodeSpec.Input.GetArgs()
		if len(args) != len(in.Args)+1 || string(args[0]) != in.Function {
			return nil, fabricReject(CodeFabricMismatch, "함수·인자 수가 intent 와 다르다")
		}
		for i, a := range in.Args {
			if string(args[i+1]) != a {
				return nil, fabricReject(CodeFabricMismatch, "인자 %d 가 intent 와 다르다", i)
			}
		}
		if creator.Mspid != mspID || !bytes.Equal(creator.IdBytes, []byte(id.CertPEM)) {
			return nil, fabricReject(CodeFabricMismatch, "제안 생성자가 키 %s 의 신원과 다르다", key.KeyID)
		}
		digest = sha256.Sum256(pp.propByte)
		txID, keep = pp.txID, pp.propByte
	case KindTransaction, KindCommit:
		pp, err := s.signedProposal(ctx, in.RequestID)
		if err != nil {
			return nil, err
		}
		txID = pp.txID
		if req.Kind == KindTransaction {
			if digest, err = checkTransaction(req.Payload, pp); err != nil {
				return nil, err
			}
		} else if digest, err = checkCommit(req.Payload, pp); err != nil {
			return nil, err
		}
	}

	// 8. HSM 서명 → low-S DER → 공개키 검증
	r, sv, err := s.Signer.SignDigest(ctx, key.KeyID, digest)
	if err != nil {
		return nil, reject(8, CodeSignFailed, "%v", err)
	}
	sig, err := signer.P256DER(r, sv)
	if err != nil {
		return nil, reject(8, CodeSignFailed, "%v", err)
	}
	pub, err := signer.P256Public(key.PublicKey)
	if err != nil || !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil, reject(8, CodeSigMismatch, "서명이 키 %s 공개키로 검증되지 않는다", key.KeyID)
	}

	// 9. 저장과 감사(한 트랜잭션)
	txIDBytes, _ := hex.DecodeString(txID)
	dbtx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return nil, reject(9, CodeStoreFailed, "%v", err)
	}
	defer func() { _ = dbtx.Rollback() }()
	if _, err := dbtx.ExecContext(ctx, `INSERT INTO signatures (request_id, kind, key_id, intent_hash, unsigned_tx_hash, tx_hash, signed_tx, payload)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, in.RequestID, req.Kind, key.KeyID, h[:], payloadHash[:], txIDBytes, sig, keep); err != nil {
		var me *mysql.MySQLError
		if errors.As(err, &me) && me.Number == 1062 {
			_ = dbtx.Rollback()
			res, eerr := s.existingFabric(ctx, in.RequestID, req.Kind, payloadHash)
			if eerr != nil || res != nil {
				return res, eerr
			}
			return nil, reject(2, CodeRequestConflict, "(request_id, kind) 예약 충돌")
		}
		return nil, reject(9, CodeStoreFailed, "%v", err)
	}
	if _, err := audit.Append(ctx, dbtx, audit.Entry{Actor: caller, Action: "SIGN_FABRIC", Subject: in.RequestID, Payload: map[string]any{
		"request_id": in.RequestID, "key_id": key.KeyID, "kind": req.Kind, "tx_id": txID, "channel": channel, "contract": in.Contract,
		"function": in.Function, "intent_hash": hex.EncodeToString(h[:]), "msp_id": mspID, "serial": id.Serial,
	}}); err != nil {
		return nil, reject(9, CodeStoreFailed, "%v", err)
	}
	if err := dbtx.Commit(); err != nil {
		return nil, reject(9, CodeStoreFailed, "%v", err)
	}
	return &FabricResponse{RequestID: in.RequestID, KeyID: key.KeyID, Kind: req.Kind, TxID: txID, Signature: sig}, nil
}

// existingFabric 은 같은 (request_id, kind)의 저장된 서명이다. 원문이 같으면 돌려주고 다르면 거부한다.
func (s *Service) existingFabric(ctx context.Context, requestID, kind string, payloadHash [32]byte) (*FabricResponse, error) {
	var keyID string
	var stored, txID, sig []byte
	err := s.DB.QueryRowContext(ctx, `SELECT key_id, unsigned_tx_hash, tx_hash, signed_tx FROM signatures WHERE request_id = ? AND kind = ?`, requestID, kind).
		Scan(&keyID, &stored, &txID, &sig)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(stored, payloadHash[:]) {
		return nil, reject(2, CodeRequestConflict, "request_id %s 의 %s 는 다른 원문으로 이미 서명됐다", requestID, kind)
	}
	return &FabricResponse{RequestID: requestID, KeyID: keyID, Kind: kind, TxID: hex.EncodeToString(txID), Signature: sig}, nil
}

// signedProposal 은 같은 요청에서 서명한 제안이다(TRANSACTION·COMMIT 대조 기준).
func (s *Service) signedProposal(ctx context.Context, requestID string) (*parsedProposal, error) {
	var pb []byte
	err := s.DB.QueryRowContext(ctx, `SELECT payload FROM signatures WHERE request_id = ? AND kind = ?`, requestID, KindProposal).Scan(&pb)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fabricReject(CodeFabricNoProposal, "요청 %s 의 제안 서명이 없다", requestID)
	}
	if err != nil {
		return nil, err
	}
	pp, _, _, _, err := parseProposalBytes(pb)
	return pp, err
}

// checkTransaction 은 보증된 트랜잭션이 서명한 제안에서 나온 것인지 확인한다: 헤더·호출 입력이 같고 보증 결과의
// proposal_hash 가 그 제안의 해시다. 체인코드 실행 결과(읽기·쓰기 집합)의 의미는 검증하지 않는다.
func checkTransaction(payload []byte, pp *parsedProposal) ([32]byte, error) {
	var zero [32]byte
	var prepared gateway.PreparedTransaction
	if err := proto.Unmarshal(payload, &prepared); err != nil || prepared.Envelope == nil {
		return zero, fabricReject(CodeFabricInvalid, "PreparedTransaction")
	}
	if prepared.TransactionId != pp.txID {
		return zero, fabricReject(CodeFabricMismatch, "transaction_id 가 서명한 제안과 다르다")
	}
	var pl common.Payload
	if err := proto.Unmarshal(prepared.Envelope.Payload, &pl); err != nil || pl.Header == nil {
		return zero, fabricReject(CodeFabricInvalid, "Envelope.Payload")
	}
	if !bytes.Equal(pl.Header.ChannelHeader, pp.chHdr) || !bytes.Equal(pl.Header.SignatureHeader, pp.sigHdr) {
		return zero, fabricReject(CodeFabricMismatch, "트랜잭션 헤더가 서명한 제안의 헤더와 다르다")
	}
	var t peer.Transaction
	if err := proto.Unmarshal(pl.Data, &t); err != nil || len(t.Actions) != 1 {
		return zero, fabricReject(CodeFabricInvalid, "Transaction(동작 1개)")
	}
	if !bytes.Equal(t.Actions[0].Header, pp.sigHdr) {
		return zero, fabricReject(CodeFabricMismatch, "동작 헤더가 서명한 제안과 다르다")
	}
	var cap_ peer.ChaincodeActionPayload
	if err := proto.Unmarshal(t.Actions[0].Payload, &cap_); err != nil || cap_.Action == nil {
		return zero, fabricReject(CodeFabricInvalid, "ChaincodeActionPayload")
	}
	if !bytes.Equal(cap_.ChaincodeProposalPayload, pp.payload) {
		return zero, fabricReject(CodeFabricMismatch, "트랜잭션의 호출 입력이 서명한 제안과 다르다")
	}
	var prp peer.ProposalResponsePayload
	if err := proto.Unmarshal(cap_.Action.ProposalResponsePayload, &prp); err != nil {
		return zero, fabricReject(CodeFabricInvalid, "ProposalResponsePayload")
	}
	ph := sha256.New()
	ph.Write(pp.chHdr)
	ph.Write(pp.sigHdr)
	ph.Write(pp.payload)
	if !bytes.Equal(ph.Sum(nil), prp.ProposalHash) {
		return zero, fabricReject(CodeFabricMismatch, "보증 결과의 proposal_hash 가 서명한 제안과 다르다")
	}
	if len(cap_.Action.Endorsements) == 0 {
		return zero, fabricReject(CodeFabricInvalid, "보증이 없다")
	}
	return sha256.Sum256(prepared.Envelope.Payload), nil
}

// checkCommit 은 커밋 상태 요청이 서명한 제안의 txID·채널·생성자에 대한 것인지 확인한다.
func checkCommit(payload []byte, pp *parsedProposal) ([32]byte, error) {
	var zero [32]byte
	var sreq gateway.SignedCommitStatusRequest
	if err := proto.Unmarshal(payload, &sreq); err != nil {
		return zero, fabricReject(CodeFabricInvalid, "SignedCommitStatusRequest")
	}
	var cr gateway.CommitStatusRequest
	if err := proto.Unmarshal(sreq.Request, &cr); err != nil {
		return zero, fabricReject(CodeFabricInvalid, "CommitStatusRequest")
	}
	if cr.TransactionId != pp.txID || cr.ChannelId != pp.channel || !bytes.Equal(cr.Identity, pp.creator) {
		return zero, fabricReject(CodeFabricMismatch, "커밋 상태 요청이 서명한 제안(txID·채널·생성자)과 다르다")
	}
	return sha256.Sum256(sreq.Request), nil
}
