//go:build integration

package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-sql-driver/mysql"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/ledger/besu/sectoken"
)

func apiDB(t *testing.T) *sql.DB {
	t.Helper()
	_, file, _, _ := runtime.Caller(0)
	pw, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "deploy", "secrets", "api_app_password"))
	if err != nil {
		t.Fatalf("비밀 파일(make up 필요): %v", err)
	}
	c := mysql.NewConfig()
	c.User, c.Passwd, c.Net, c.Addr, c.DBName = "api_app", strings.TrimSpace(string(pw)), "tcp", "127.0.0.1:3306", "api"
	c.ParseTime = true
	db, err := sql.Open("mysql", c.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("DB 접속(make up 필요): %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// chain 은 시험용 임시 키(가스비 0 네트워크)로 종목을 배포하고 이벤트를 만든다. HSM 키와 무관하다.
type chain struct {
	t     *testing.T
	a     *besu.Adapter
	eth   *ethclient.Client
	key   *ecdsa.PrivateKey
	from  common.Address
	nonce uint64
	abi   *abi.ABI
}

func newChain(t *testing.T) *chain {
	t.Helper()
	a, eth, err := besu.Dial(context.Background(), "http://127.0.0.1:8545", besu.Config{ChainID: 20261124, GasLimit: 300000, DeployGasLimit: 3000000})
	if err != nil {
		t.Fatalf("RPC(make up 필요): %v", err)
	}
	t.Cleanup(eth.Close)
	key, _ := crypto.GenerateKey()
	parsed, _ := sectoken.SecurityTokenMetaData.GetAbi()
	return &chain{t: t, a: a, eth: eth, key: key, from: crypto.PubkeyToAddress(key.PublicKey), abi: parsed}
}

// send 는 tx 를 서명·제출하고 해시를 돌려준다(확정은 기다리지 않는다).
func (c *chain) send(to *common.Address, data []byte, gas uint64) common.Hash {
	c.t.Helper()
	id := big.NewInt(20261124)
	tx, err := types.SignNewTx(c.key, types.LatestSignerForChainID(id), &types.DynamicFeeTx{ChainID: id, Nonce: c.nonce, GasTipCap: big.NewInt(0),
		GasFeeCap: big.NewInt(0), Gas: gas, To: to, Value: big.NewInt(0), Data: data})
	if err != nil {
		c.t.Fatal(err)
	}
	c.nonce++
	raw, _ := tx.MarshalBinary()
	h, err := c.a.Submit(context.Background(), raw)
	if err != nil {
		c.t.Fatal(err)
	}
	return h
}

func (c *chain) wait(h common.Hash) *ledger.Receipt {
	c.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		r, err := c.a.Receipt(context.Background(), h)
		if err == nil {
			if !r.Succeeded() {
				c.t.Fatalf("tx 실패 %s", h.Hex())
			}
			return r
		}
		if !errors.Is(err, ledger.ErrReceiptNotFound) || time.Now().After(deadline) {
			c.t.Fatalf("영수증 %s: %v", h.Hex(), err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (c *chain) call(contract common.Address, method string, args ...any) common.Hash {
	c.t.Helper()
	data, err := c.abi.Pack(method, args...)
	if err != nil {
		c.t.Fatal(err)
	}
	return c.send(&contract, data, 300000)
}

// deployWithEvents 는 종목을 배포하고 여러 블록에 걸친 이벤트를 만든다. 배포 블록과 마지막 블록을 돌려준다.
func (c *chain) deployWithEvents(rounds int) (common.Address, uint64, uint64) {
	c.t.Helper()
	ctor, _ := c.abi.Pack("", "IT Registry", "KRITREG", c.from)
	r := c.wait(c.send(nil, append(besu.SecurityTokenCode(), ctor...), 3000000))
	contract := *r.ContractAddress
	c.wait(c.call(contract, "grantRole", crypto.Keccak256Hash([]byte("ISSUER_ROLE")), c.from))
	c.wait(c.call(contract, "grantRole", crypto.Keccak256Hash([]byte("TRANSFER_AGENT_ROLE")), c.from))
	c.wait(c.call(contract, "setAgentInstitution", c.from, "inst-a"))
	a1 := common.HexToAddress("0x70997970C51812dc3A010C7d01b50e0d17dc79C8")
	a2 := common.HexToAddress("0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC")
	c.call(contract, "registerAccount", a1, "inst-a")
	c.wait(c.call(contract, "registerAccount", a2, "inst-a"))
	var last *ledger.Receipt
	for i := 0; i < rounds; i++ {
		c.call(contract, "issue", a1, big.NewInt(int64(100+i)))
		last = c.wait(c.call(contract, "transferByAgent", a1, a2, big.NewInt(1)))
	}
	return contract, r.BlockNumber, last.BlockNumber
}

type fx struct {
	db       *sql.DB
	ledger   string
	contract common.Address
	c        *chain
	deploy   uint64
	last     uint64
}

func setup(t *testing.T, rounds int) *fx {
	t.Helper()
	db := apiDB(t)
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	f := &fx{db: db, ledger: "it-reg-" + hex.EncodeToString(b), c: newChain(t)}
	f.contract, f.deploy, f.last = f.c.deployWithEvents(rounds)
	if _, err := db.Exec(`INSERT INTO ledger_cursor (ledger_id, contract_address, last_block) VALUES (?, ?, ?)`, f.ledger, f.contract.Hex(), f.deploy-1); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM registry_events WHERE ledger_id = ?`, f.ledger)
		_, _ = db.Exec(`DELETE FROM ledger_cursor WHERE ledger_id = ?`, f.ledger)
	})
	return f
}

// onChain 은 [배포 블록, 마지막 블록] 의 로그 수를 노드에서 직접 센다(어댑터 디코딩과 별개로).
func (f *fx) onChain(t *testing.T) int {
	t.Helper()
	logs, err := f.c.eth.FilterLogs(context.Background(), ethereumQuery(f.contract, f.deploy, f.last))
	if err != nil {
		t.Fatal(err)
	}
	return len(logs)
}

func (f *fx) stored(t *testing.T) (total, distinct int) {
	t.Helper()
	if err := f.db.QueryRow(`SELECT COUNT(*), COUNT(DISTINCT tx_hash, log_index) FROM registry_events WHERE ledger_id = ? AND block_number <= ?`,
		f.ledger, f.last).Scan(&total, &distinct); err != nil {
		t.Fatal(err)
	}
	return
}

func (f *fx) cursor(t *testing.T) uint64 {
	var n uint64
	if err := f.db.QueryRow(`SELECT last_block FROM ledger_cursor WHERE ledger_id = ?`, f.ledger).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// 작업자가 이벤트를 넣은 뒤 커밋 전에 죽으면 그 구간은 저장되지 않고 커서도 그대로다.
// 다시 살린 작업자가 같은 구간부터 읽어, 빠짐·중복 없이 체인의 로그 수와 같아진다(작업지시서 T3.4 완료 기준).
func TestKillMidBatchNoLossNoDuplicate(t *testing.T) {
	f := setup(t, 4)
	ctx := context.Background()
	want := f.onChain(t)
	if want < 10 {
		t.Fatalf("시험 이벤트가 너무 적다(%d)", want)
	}
	errKilled := errors.New("작업자 중단(시험)")
	batches := 0
	w := &Worker{DB: f.db, LedgerID: f.ledger, Source: f.c.a, MaxBlocks: 3}
	// 세 번째 구간에서 이벤트를 넣은 뒤 커밋 전에 죽는다.
	w.beforeCommit = func(_ common.Address, inserted int) error {
		batches++
		if batches == 3 {
			if inserted == 0 {
				batches-- // 이벤트가 없는 구간이면 다음 구간에서 죽인다
				return nil
			}
			return errKilled
		}
		return nil
	}
	var killedAt uint64
	for {
		before := f.cursor(t)
		_, err := w.RunOnce(ctx)
		if errors.Is(err, errKilled) {
			killedAt = before
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if f.cursor(t) >= f.last {
			t.Fatal("중단 지점에 닿기 전에 끝났다")
		}
	}
	if f.cursor(t) != killedAt {
		t.Fatalf("중단된 구간의 커서가 움직였다: %d → %d", killedAt, f.cursor(t))
	}
	var afterKill int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM registry_events WHERE ledger_id = ? AND block_number > ?`, f.ledger, killedAt).Scan(&afterKill)
	if afterKill != 0 {
		t.Fatalf("중단된 구간의 이벤트 %d 건이 남았다", afterKill)
	}

	// 다시 살린다(새 작업자, 훅 없음).
	w2 := &Worker{DB: f.db, LedgerID: f.ledger, Source: f.c.a, MaxBlocks: 3}
	for f.cursor(t) < f.last {
		if _, err := w2.RunOnce(ctx); err != nil {
			t.Fatal(err)
		}
	}
	total, distinct := f.stored(t)
	if total != want || distinct != want {
		t.Fatalf("저장 %d건(서로 다른 %d건), 체인 %d건", total, distinct, want)
	}
	// 한 번 더 돌아도 늘지 않는다.
	if _, err := w2.RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if total2, _ := f.stored(t); total2 != want {
		t.Fatalf("재실행 후 %d건", total2)
	}
	// 저장 내용 확인: 이벤트 이름별 건수와 디코딩된 값
	evs, err := List(ctx, f.db, f.ledger, f.contract.Hex(), 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]int{}
	for _, e := range evs {
		names[e.Event]++
		if e.Event == "Transferred" && (e.Payload["amount"] != "1" || e.Payload["agent"] != f.c.from.Hex()) {
			t.Fatalf("Transferred 내용 %v", e.Payload)
		}
	}
	if names["Issued"] != 4 || names["Transferred"] != 4 || names["AccountRegistered"] != 2 || names["RoleGranted"] != 3 {
		t.Fatalf("이벤트 건수 %v", names)
	}
}

// 두 작업자가 동시에 돌아도 중복 저장이 없다(커서 행 잠금).
func TestConcurrentWorkersNoDuplicate(t *testing.T) {
	f := setup(t, 2)
	ctx := context.Background()
	want := f.onChain(t)
	var wg sync.WaitGroup
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := &Worker{DB: f.db, LedgerID: f.ledger, Source: f.c.a, MaxBlocks: 2}
			for j := 0; j < 50 && f.cursor(t) < f.last; j++ {
				if _, err := w.RunOnce(ctx); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	wg.Wait()
	total, distinct := f.stored(t)
	if total != want || distinct != want {
		t.Fatalf("저장 %d건(서로 다른 %d건), 체인 %d건", total, distinct, want)
	}
}

func ethereumQuery(contract common.Address, from, to uint64) ethereum.FilterQuery {
	return ethereum.FilterQuery{FromBlock: new(big.Int).SetUint64(from), ToBlock: new(big.Int).SetUint64(to), Addresses: []common.Address{contract}}
}
