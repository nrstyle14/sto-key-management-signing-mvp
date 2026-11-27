package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/alarm"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/audit"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/recon"
	"github.com/da-infra/sto-key-management-signing-mvp/internal/workflow"
)

// 읽기 전용 웹(D-9, T4.3). 별도 포트에서 GET / 한 장만 제공한다. 쓰기 기능이 없고, 기안·승인·키 작업은 CLI 로만 한다.
// 인증이 없으므로 compose 에서 127.0.0.1 로만 연다(설계서 14절 한계). 권리자 이름 같은 연계장부 개인정보는 보여 주지 않는다.

type webFreeze struct {
	FreezeID   string     `json:"freeze_id"`
	Scope      string     `json:"scope"`
	Target     string     `json:"target"`
	Reason     string     `json:"reason"`
	FrozenBy   string     `json:"frozen_by"`
	FrozenAt   time.Time  `json:"frozen_at"`
	ReleasedAt *time.Time `json:"released_at"`
}

type webHead struct {
	Seq  uint64
	Hash string
	Err  string
}

type webPage struct {
	Now          time.Time
	Ledger       string
	Requests     []workflow.Request
	RequestsErr  string
	Keys         []workflow.KeyInfo
	KeysErr      string
	Freezes      []webFreeze
	FreezesErr   string
	Alarms       []alarm.Alarm
	AlarmsErr    string
	APIHead      webHead
	SignerHead   webHead
	ReconRuns    []recon.Run
	ReconLatest  *recon.Run
	ReconErr     string
	StatusCounts map[workflow.Status]int
}

func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

var webTmpl = template.Must(template.New("page").Funcs(template.FuncMap{
	"short": short,
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "-"
		}
		return t.UTC().Format("01-02 15:04:05")
	},
	"tsp": func(t *time.Time) string {
		if t == nil {
			return "-"
		}
		return t.UTC().Format("01-02 15:04:05")
	},
	"function": func(raw json.RawMessage) string {
		var v struct {
			Function string `json:"function"`
		}
		_ = json.Unmarshal(raw, &v)
		return v.Function
	},
}).Parse(webHTML))

// webHandler 는 GET / 만 받는다. 다른 경로·메서드는 404·405 다.
func (a *app) webHandler(log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		p := a.collect(ctx)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		if err := webTmpl.Execute(w, p); err != nil {
			log.Warn("웹 화면 렌더링", "err", err)
		}
	})
	return mux
}

func (a *app) collect(ctx context.Context) *webPage {
	p := &webPage{Now: time.Now().UTC(), Ledger: a.cfg.Ledger.ID, StatusCounts: map[workflow.Status]int{}}
	if reqs, err := a.wf.List(ctx, "", 30); err != nil {
		p.RequestsErr = err.Error()
	} else {
		p.Requests = reqs
	}
	rows, err := a.db.QueryContext(ctx, `SELECT status, COUNT(*) FROM requests WHERE ledger_id = ? GROUP BY status`, a.cfg.Ledger.ID)
	if err == nil {
		for rows.Next() {
			var s workflow.Status
			var n int
			if rows.Scan(&s, &n) == nil {
				p.StatusCounts[s] = n
			}
		}
		rows.Close()
	}
	if keys, err := a.signer.Keys(ctx); err != nil {
		p.KeysErr = "서명 서버 응답 없음: " + err.Error()
	} else {
		p.Keys = keys
	}
	var fz struct {
		Freezes []webFreeze `json:"freezes"`
	}
	if raw, err := a.signer.fetch(ctx, "/v1/freezes"); err != nil {
		p.FreezesErr = "서명 서버 응답 없음: " + err.Error()
	} else if err := json.Unmarshal(raw, &fz); err != nil {
		p.FreezesErr = err.Error()
	} else {
		p.Freezes = fz.Freezes
	}
	if al, err := alarm.List(ctx, a.db, 20); err != nil {
		p.AlarmsErr = err.Error()
	} else {
		p.Alarms = al
	}
	if seq, h, err := audit.HeadOf(ctx, a.db); err != nil {
		p.APIHead.Err = err.Error()
	} else {
		p.APIHead = webHead{Seq: seq, Hash: hex.EncodeToString(h[:])}
	}
	var sh struct {
		Seq  uint64 `json:"seq"`
		Hash string `json:"hash"`
	}
	if raw, err := a.signer.fetch(ctx, "/v1/audit/head"); err != nil {
		p.SignerHead.Err = "서명 서버 응답 없음"
	} else if err := json.Unmarshal(raw, &sh); err != nil {
		p.SignerHead.Err = err.Error()
	} else {
		p.SignerHead = webHead{Seq: sh.Seq, Hash: sh.Hash}
	}
	if runs, err := recon.List(ctx, a.db, 10); err != nil {
		p.ReconErr = err.Error()
	} else {
		p.ReconRuns = runs
		if latest, err := recon.Get(ctx, a.db, 0); err == nil {
			p.ReconLatest = latest
		}
	}
	return p
}

// serveWeb 은 읽기 전용 웹을 평문 HTTP 로 띄운다(ctx 가 끝나면 닫는다).
func serveWeb(ctx context.Context, log *slog.Logger, addr string, h http.Handler) {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("읽기 전용 웹", "listen", addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Error("읽기 전용 웹 종료", "err", err)
	}
}

const webHTML = `<!doctype html>
<html lang="ko"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="5">
<title>STO 키 관리 현황</title>
<style>
:root{--bg:#f7f7f5;--fg:#1d1d1b;--mut:#6b6b66;--line:#deded8;--card:#fff;--ok:#1f7a4d;--warn:#a15c00;--bad:#b42318;--acc:#2f5aa8}
@media (prefers-color-scheme: dark){:root{--bg:#161616;--fg:#e9e9e6;--mut:#9a9a94;--line:#2e2e2b;--card:#1f1f1e;--ok:#55c08a;--warn:#e0a040;--bad:#ef6b5e;--acc:#7da2e8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,"Apple SD Gothic Neo","Noto Sans KR",sans-serif}
header{padding:16px 20px;border-bottom:1px solid var(--line);display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline}
h1{font-size:18px;margin:0}header span{color:var(--mut)}
main{padding:16px 20px;display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(420px,1fr))}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px;overflow-x:auto}
section.wide{grid-column:1/-1}h2{font-size:14px;margin:0 0 8px}
table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;padding:4px 6px;border-bottom:1px solid var(--line);white-space:nowrap}
th{color:var(--mut);font-weight:600}code{font:12px ui-monospace,Menlo,monospace}
.b{display:inline-block;padding:0 6px;border-radius:4px;font-size:11.5px;font-weight:600;border:1px solid currentColor}
.CONFIRMED,.ACTIVE,.OK{color:var(--ok)}.FAILED,.REJECTED,.FROZEN,.MISMATCH,.ERROR,.DESTROYED{color:var(--bad)}
.PENDING_APPROVAL,.APPROVED,.SIGNED,.SUBMITTED,.PENDING,.RUNNING{color:var(--warn)}.RETIRED,.EXPIRED{color:var(--mut)}
.err{color:var(--bad)}.mut{color:var(--mut)}.kv{display:flex;gap:16px;flex-wrap:wrap}.kv div{min-width:160px}
@media (max-width:480px){main{padding:12px 16px;grid-template-columns:1fr}header{padding:12px 16px}}
</style></head><body>
<header><h1>STO 키 관리·서명 현황</h1><span>원장 {{.Ledger}}</span><span>읽기 전용 · 5초마다 새로 고침 · {{ts .Now}} UTC</span></header>
<main>
<section><h2>감사 체인 머리</h2><div class="kv">
<div>업무 서버(api)<br>{{if .APIHead.Err}}<span class="err">{{.APIHead.Err}}</span>{{else}}seq <b>{{.APIHead.Seq}}</b><br><code>{{short .APIHead.Hash 16}}</code>{{end}}</div>
<div>서명 서버(signer)<br>{{if .SignerHead.Err}}<span class="err">{{.SignerHead.Err}}</span>{{else}}seq <b>{{.SignerHead.Seq}}</b><br><code>{{short .SignerHead.Hash 16}}</code>{{end}}</div>
</div><p class="mut">요청 상태: {{range $s, $n := .StatusCounts}}<span class="b {{$s}}">{{$s}} {{$n}}</span> {{end}}</p></section>

<section><h2>대사</h2>{{if .ReconErr}}<p class="err">{{.ReconErr}}</p>{{end}}
{{with .ReconLatest}}<p>최근 #{{.RunID}} {{if .Scope}}{{.Scope}}{{else}}전체{{end}} <span class="b {{.Status}}">{{.Status}}</span> 불일치 {{.DiffCount}}건 · {{ts .StartedAt}}</p>
{{if .Diffs}}<table><tr><th>종목</th><th>비교</th><th>계좌</th><th>원장</th><th>연계장부</th><th>블록</th></tr>
{{range .Diffs}}<tr><td>{{.IssueCode}}</td><td>{{.Kind}}</td><td>{{if .AccountNo}}{{.AccountNo}}{{else}}<code>{{short .Address 12}}</code>{{end}}</td><td>{{.Expected}}</td><td>{{.Actual}}</td><td>{{.BlockNumber}}</td></tr>{{end}}</table>{{end}}{{else}}<p class="mut">대사 기록 없음</p>{{end}}
{{if .ReconRuns}}<table><tr><th>#</th><th>범위</th><th>상태</th><th>불일치</th><th>시각</th></tr>{{range .ReconRuns}}<tr><td>{{.RunID}}</td><td>{{if .Scope}}{{.Scope}}{{else}}전체{{end}}</td><td><span class="b {{.Status}}">{{.Status}}</span></td><td>{{.DiffCount}}</td><td>{{ts .StartedAt}}</td></tr>{{end}}</table>{{end}}</section>

<section class="wide"><h2>업무 요청(최근 30건)</h2>{{if .RequestsErr}}<p class="err">{{.RequestsErr}}</p>{{end}}
<table><tr><th>요청</th><th>기관</th><th>유형</th><th>함수</th><th>상태</th><th>서명 키 주소</th><th>tx</th><th>블록</th><th>오류</th><th>갱신</th></tr>
{{range .Requests}}<tr><td><code>{{.RequestID}}</code></td><td>{{.InstitutionID}}</td><td>{{.Type}}</td><td>{{function .Intent}}</td><td><span class="b {{.Status}}">{{.Status}}</span></td><td><code>{{short .SignerAddress 12}}</code></td><td><code>{{short .TxHash 12}}</code></td><td>{{with .BlockNumber}}{{.}}{{end}}</td><td class="err">{{short .Error 60}}</td><td>{{ts .UpdatedAt}}</td></tr>{{end}}</table></section>

<section><h2>키 레지스트리</h2>{{if .KeysErr}}<p class="err">{{.KeysErr}}</p>{{end}}
<table><tr><th>키</th><th>기관</th><th>용도</th><th>상태</th><th>주소</th></tr>
{{range .Keys}}<tr><td><code>{{short .KeyID 30}}</code></td><td>{{.InstitutionID}}</td><td>{{.Purpose}}</td><td><span class="b {{.Status}}">{{.Status}}</span></td><td><code>{{short .Address 12}}</code></td></tr>{{end}}</table></section>

<section><h2>동결</h2>{{if .FreezesErr}}<p class="err">{{.FreezesErr}}</p>{{end}}
{{if .Freezes}}<table><tr><th>대상</th><th>범위</th><th>사유</th><th>동결</th><th>해제</th></tr>
{{range .Freezes}}<tr><td><code>{{short .Target 30}}</code></td><td>{{.Scope}}</td><td>{{short .Reason 30}}</td><td>{{.FrozenBy}} {{ts .FrozenAt}}</td><td>{{if .ReleasedAt}}{{tsp .ReleasedAt}}{{else}}<span class="b FROZEN">동결 중</span>{{end}}</td></tr>{{end}}</table>{{else}}<p class="mut">동결 기록 없음</p>{{end}}</section>

<section><h2>알람(최근 20건)</h2>{{if .AlarmsErr}}<p class="err">{{.AlarmsErr}}</p>{{end}}
{{if .Alarms}}<table><tr><th>규칙</th><th>대상</th><th>시각</th></tr>{{range .Alarms}}<tr><td>{{.Rule}}</td><td><code>{{short .Subject 40}}</code></td><td>{{ts .CreatedAt}}</td></tr>{{end}}</table>{{else}}<p class="mut">알람 없음</p>{{end}}</section>
</main></body></html>`
