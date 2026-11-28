package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/approval"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/policy"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/signsvc"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// signerClient 는 서명 서버(signerd) 호출이다: 명부 조회(workflow.Directory)와 서명 요청(workflow.SignerClient).
// 명부는 짧게 캐시하고, 서명 서버가 응답하지 않으면 마지막으로 받은 값을 쓴다(서명 서버 장애 중에도 승인 접수).
type signerClient struct {
	http *http.Client
	base string
	ttl  time.Duration

	mu    sync.Mutex
	cache map[string]cached
}

type cached struct {
	at  time.Time
	raw []byte
}

func newSignerClient(c *http.Client, base string) *signerClient {
	return &signerClient{http: c, base: base, ttl: 30 * time.Second, cache: map[string]cached{}}
}

func (c *signerClient) get(ctx context.Context, path string, out any) error {
	c.mu.Lock()
	hit, ok := c.cache[path]
	c.mu.Unlock()
	if ok && time.Since(hit.at) < c.ttl {
		return json.Unmarshal(hit.raw, out)
	}
	raw, err := c.fetch(ctx, path)
	if err != nil {
		if ok { // 서명 서버 장애: 마지막 값을 쓴다
			return json.Unmarshal(hit.raw, out)
		}
		return err
	}
	c.mu.Lock()
	c.cache[path] = cached{at: time.Now(), raw: raw}
	c.mu.Unlock()
	return json.Unmarshal(raw, out)
}

// getFresh 는 캐시를 쓰지 않고 읽되, 서명 서버가 응답하지 않으면 마지막으로 받은 값을 쓴다.
func (c *signerClient) getFresh(ctx context.Context, path string, out any) error {
	raw, err := c.fetch(ctx, path)
	if err != nil {
		c.mu.Lock()
		hit, ok := c.cache[path]
		c.mu.Unlock()
		if ok {
			return json.Unmarshal(hit.raw, out)
		}
		return err
	}
	c.mu.Lock()
	c.cache[path] = cached{at: time.Now(), raw: raw}
	c.mu.Unlock()
	return json.Unmarshal(raw, out)
}

func (c *signerClient) fetch(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("서명 서버 %s: HTTP %d", path, resp.StatusCode)
	}
	return raw, nil
}

func (c *signerClient) Policies(ctx context.Context) ([]policy.Policy, error) {
	var v struct {
		Policies []policy.Policy `json:"policies"`
	}
	// 화이트리스트 추가(D-22) 직후의 기안이 사전 검사에서 막히지 않게 정책은 캐시하지 않는다.
	err := c.getFresh(ctx, "/v1/policies", &v)
	return v.Policies, err
}

func (c *signerClient) Approvers(ctx context.Context) ([]approval.Approver, error) {
	var v struct {
		Approvers []approval.Approver `json:"approvers"`
	}
	return v.Approvers, c.get(ctx, "/v1/approvers", &v)
}

func (c *signerClient) Keys(ctx context.Context) ([]workflow.KeyInfo, error) {
	var v struct {
		Keys []workflow.KeyInfo `json:"keys"`
	}
	// 키 상태(ACTIVE·동결 등)는 서명 직전에 쓰므로 캐시하지 않는다.
	raw, err := c.fetch(ctx, "/v1/keys")
	if err != nil {
		return nil, err
	}
	return v.Keys, json.Unmarshal(raw, &v)
}

// SignTx 는 서명을 요청한다. 2xx 는 결과, 서명 서버의 거부(4xx, 단계·코드 있음)는 *signsvc.Rejection,
// 그 밖(연결 실패, 5xx)은 일시 오류다.
func (c *signerClient) SignTx(ctx context.Context, sreq signsvc.Request) (*signsvc.Response, error) {
	body, err := json.Marshal(sreq)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/sign/tx", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		var res signsvc.Response
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, err
		}
		return &res, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		var rj signsvc.Rejection
		if json.Unmarshal(raw, &rj) == nil && rj.Code != "" && rj.Step > 0 {
			return nil, &rj
		}
		var e transport.ErrorBody
		_ = json.Unmarshal(raw, &e)
		return nil, &signsvc.Rejection{Step: 0, Code: e.Code, Msg: fmt.Sprintf("HTTP %d %s", resp.StatusCode, e.Message)}
	default:
		return nil, fmt.Errorf("서명 서버 HTTP %d", resp.StatusCode)
	}
}

// PushAPIHead 는 api 감사 체인 머리를 서명 서버에 알린다(체크포인트용, 설계서 8절).
func (c *signerClient) PushAPIHead(ctx context.Context, seq uint64, hash string) error {
	body, _ := json.Marshal(map[string]any{"seq": seq, "hash": hash})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/audit/api-head", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("서명 서버 HTTP %d", resp.StatusCode)
	}
	return nil
}

// SignFabric 은 Fabric 원문 서명을 요청한다(설계서 10.5, D-26). 거부(4xx)는 *signsvc.Rejection, 그 밖은 일시 오류다.
func (c *signerClient) SignFabric(ctx context.Context, sreq signsvc.FabricRequest) (*signsvc.FabricResponse, error) {
	body, err := json.Marshal(sreq)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/v1/sign/fabric", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: 서명 서버 호출: %v", workflow.ErrTransient, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	switch {
	case resp.StatusCode == http.StatusOK:
		var res signsvc.FabricResponse
		if err := json.Unmarshal(raw, &res); err != nil {
			return nil, err
		}
		return &res, nil
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		var rj signsvc.Rejection
		if json.Unmarshal(raw, &rj) == nil && rj.Code != "" && rj.Step > 0 {
			return nil, &rj
		}
		var e transport.ErrorBody
		_ = json.Unmarshal(raw, &e)
		return nil, &signsvc.Rejection{Step: 0, Code: e.Code, Msg: fmt.Sprintf("HTTP %d %s", resp.StatusCode, e.Message)}
	default:
		return nil, fmt.Errorf("%w: 서명 서버 HTTP %d", workflow.ErrTransient, resp.StatusCode)
	}
}

// FabricIdentity 는 (원장, 기관, 용도)의 ACTIVE Fabric 신원 키 인증서와 MSP 다(캐시하지 않는다: 교체·폐기 직후 반영).
// 폐기된 신원도 돌려준다: 사용 가능 여부는 서명 서버가 4단계에서 판단해 거부한다(요청이 APPROVED 에 머물지 않게).
func (c *signerClient) FabricIdentity(ctx context.Context, ledgerID, institutionID, purpose string) ([]byte, string, error) {
	keys, err := c.Keys(ctx)
	if err != nil {
		return nil, "", err
	}
	keyID := ""
	for _, k := range keys {
		if k.LedgerID == ledgerID && k.InstitutionID == institutionID && k.Purpose == purpose && k.Status == "ACTIVE" {
			keyID = k.KeyID
		}
	}
	if keyID == "" {
		return nil, "", fmt.Errorf("(%s, %s, %s) 의 ACTIVE 키가 없다", ledgerID, institutionID, purpose)
	}
	raw, err := c.fetch(ctx, "/v1/fabric/identities")
	if err != nil {
		return nil, "", err
	}
	var v struct {
		Identities []struct {
			KeyID   string `json:"key_id"`
			MSPID   string `json:"msp_id"`
			CertPEM string `json:"cert_pem"`
			Status  string `json:"status"`
		} `json:"identities"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, "", err
	}
	for _, i := range v.Identities {
		if i.KeyID == keyID {
			return []byte(i.CertPEM), i.MSPID, nil
		}
	}
	return nil, "", fmt.Errorf("키 %s 에 Fabric 신원이 없다", keyID)
}
