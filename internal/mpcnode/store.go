package mpcnode

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	zkpaillier "github.com/getamis/alice/crypto/zkproof/paillier"
)

// 조각 파일 형식(설계서 6.4 MPC 서명기). 파일은 노드 저장 키(AES-256-GCM)로 암호화하고 AAD 는 "노드 ID/키 ID"다.

var keyIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// ErrNotFound 는 조각이 없다는 것이다.
var ErrNotFound = errors.New("mpcnode: 조각이 없다")

type pointRec struct{ X, Y string }

type pedRec struct{ N, S, T string }

type bkRec struct {
	X    string
	Rank uint32
}

// record 는 조각 파일의 평문이다(메모리에서만, 디스크에는 암호문).
type record struct {
	KeyID     string
	Node      string
	PublicKey pointRec
	Share     string
	P, Q      string
	Partial   map[string]pointRec
	Ped       map[string]pedRec
	Bks       map[string]bkRec
	Rid       []byte
}

// Share 는 서명에 쓰는 조각과 공개 매개변수다.
type Share struct {
	KeyID     string
	PublicKey *pt.ECPoint
	Share     *big.Int
	Paillier  *paillier.Paillier
	Partial   map[string]*pt.ECPoint
	Ped       map[string]*zkpaillier.PederssenOpenParameter
	Bks       map[string]*birkhoffinterpolation.BkParameter
	Rid       []byte
}

func dec(s string) (*big.Int, error) {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("mpcnode: 수 형식 %q", s)
	}
	return v, nil
}

func toPoint(r pointRec) (*pt.ECPoint, error) {
	x, err := dec(r.X)
	if err != nil {
		return nil, err
	}
	y, err := dec(r.Y)
	if err != nil {
		return nil, err
	}
	return pt.NewECPoint(elliptic.Secp256k1(), x, y)
}

func fromPoint(p *pt.ECPoint) pointRec { return pointRec{X: p.GetX().String(), Y: p.GetY().String()} }

func (s *Share) toRecord(node string) record {
	p, q := s.Paillier.GetPQ()
	r := record{KeyID: s.KeyID, Node: node, PublicKey: fromPoint(s.PublicKey), Share: s.Share.String(), P: p.String(), Q: q.String(),
		Partial: map[string]pointRec{}, Ped: map[string]pedRec{}, Bks: map[string]bkRec{}, Rid: s.Rid}
	for id, v := range s.Partial {
		r.Partial[id] = fromPoint(v)
	}
	for id, v := range s.Ped {
		r.Ped[id] = pedRec{N: v.GetN().String(), S: v.GetS().String(), T: v.GetT().String()}
	}
	for id, v := range s.Bks {
		r.Bks[id] = bkRec{X: v.GetX().String(), Rank: v.GetRank()}
	}
	return r
}

func (r record) toShare() (*Share, error) {
	s := &Share{KeyID: r.KeyID, Partial: map[string]*pt.ECPoint{}, Ped: map[string]*zkpaillier.PederssenOpenParameter{},
		Bks: map[string]*birkhoffinterpolation.BkParameter{}, Rid: r.Rid}
	var err error
	if s.PublicKey, err = toPoint(r.PublicKey); err != nil {
		return nil, err
	}
	if s.Share, err = dec(r.Share); err != nil {
		return nil, err
	}
	p, err := dec(r.P)
	if err != nil {
		return nil, err
	}
	q, err := dec(r.Q)
	if err != nil {
		return nil, err
	}
	if s.Paillier, err = paillier.NewPaillierWithGivenPrimes(p, q); err != nil {
		return nil, fmt.Errorf("mpcnode: Paillier 키 복원: %w", err)
	}
	for id, v := range r.Partial {
		if s.Partial[id], err = toPoint(v); err != nil {
			return nil, err
		}
	}
	for id, v := range r.Ped {
		n, err1 := dec(v.N)
		sv, err2 := dec(v.S)
		t, err3 := dec(v.T)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, err
		}
		s.Ped[id] = zkpaillier.NewPedersenOpenParameter(n, sv, t)
	}
	for id, v := range r.Bks {
		x, err := dec(v.X)
		if err != nil {
			return nil, err
		}
		s.Bks[id] = birkhoffinterpolation.NewBkParameter(x, v.Rank)
	}
	return s, nil
}

// Store 는 노드의 조각 저장소다. 확정 조각은 <dir>/<키>.share, 확정 전 결과는 <키>.staged 다.
type Store struct {
	Dir  string
	Node string
	aead cipher.AEAD
}

// NewStore 는 32바이트 저장 키로 저장소를 연다. 디렉터리는 0700 으로 만든다.
func NewStore(dir, node string, key []byte) (*Store, error) {
	if len(key) != 32 {
		return nil, errors.New("mpcnode: 저장 키는 32바이트다")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir, Node: node, aead: aead}, nil
}

func (st *Store) path(keyID, ext string) (string, error) {
	if !keyIDRe.MatchString(keyID) {
		return "", fmt.Errorf("mpcnode: 키 ID 형식 %q", keyID)
	}
	return filepath.Join(st.Dir, keyID+ext), nil
}

func (st *Store) aad(keyID string) []byte { return []byte(st.Node + "/" + keyID) }

func (st *Store) write(path, keyID string, s *Share) error {
	plain, err := json.Marshal(s.toRecord(st.Node))
	if err != nil {
		return err
	}
	defer clear(plain)
	nonce := make([]byte, st.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	out := st.aead.Seal(nonce, nonce, plain, st.aad(keyID))
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Stage 는 키 생성 결과를 확정 전 파일로 쓴다. 이미 확정된 조각이 있으면 거부한다.
func (st *Store) Stage(s *Share) error {
	if _, err := st.Load(s.KeyID); err == nil {
		return fmt.Errorf("mpcnode: 키 %s 조각이 이미 있다", s.KeyID)
	}
	p, err := st.path(s.KeyID, ".staged")
	if err != nil {
		return err
	}
	return st.write(p, s.KeyID, s)
}

// Commit 은 확정 전 파일을 확정한다.
func (st *Store) Commit(keyID string) error {
	staged, err := st.path(keyID, ".staged")
	if err != nil {
		return err
	}
	final, _ := st.path(keyID, ".share")
	if _, err := os.Stat(final); err == nil {
		return fmt.Errorf("mpcnode: 키 %s 조각이 이미 확정돼 있다", keyID)
	}
	if _, err := os.Stat(staged); err != nil {
		return fmt.Errorf("mpcnode: 키 %s 의 확정 전 결과가 없다", keyID)
	}
	return os.Rename(staged, final)
}

// DiscardStaged 는 확정 전 파일을 지운다(실패·재시도).
func (st *Store) DiscardStaged(keyID string) error {
	p, err := st.path(keyID, ".staged")
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// Load 는 확정 조각을 읽는다.
func (st *Store) Load(keyID string) (*Share, error) {
	p, err := st.path(keyID, ".share")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	n := st.aead.NonceSize()
	if len(raw) < n {
		return nil, errors.New("mpcnode: 조각 파일이 손상됐다")
	}
	plain, err := st.aead.Open(nil, raw[:n], raw[n:], st.aad(keyID))
	if err != nil {
		return nil, errors.New("mpcnode: 조각 파일 복호화 실패(다른 노드·키의 파일이거나 변조)")
	}
	defer clear(plain)
	var r record
	if err := json.Unmarshal(plain, &r); err != nil {
		return nil, err
	}
	if r.KeyID != keyID || r.Node != st.Node {
		return nil, errors.New("mpcnode: 조각 파일의 키·노드가 다르다")
	}
	return r.toShare()
}

// Destroy 는 확정·확정 전 파일을 모두 지운다. 지운 뒤 남은 파일 수를 돌려준다(0 이어야 한다).
func (st *Store) Destroy(keyID string) (int, error) {
	n := 0
	for _, ext := range []string{".share", ".staged"} {
		p, err := st.path(keyID, ext)
		if err != nil {
			return 0, err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return 0, err
		}
		if _, err := os.Stat(p); err == nil {
			n++
		}
	}
	return n, nil
}
