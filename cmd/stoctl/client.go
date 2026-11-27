package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/transport"
)

// client 는 stoctl 인증서로 접속하는 mTLS 클라이언트다.
type client struct {
	http *http.Client
	base string
}

func (g *globals) client(base string) (*client, error) {
	cfg, err := transport.ClientTLSConfig(transport.TLSFiles{
		CA:   filepath.Join(g.certs, "ca.crt"),
		Cert: filepath.Join(g.certs, "stoctl.crt"),
		Key:  filepath.Join(g.certs, "stoctl.key"),
	}, "localhost")
	if err != nil {
		return nil, err
	}
	return &client{http: transport.NewClient(cfg, 30*time.Second), base: base}, nil
}

// APIError 는 서버의 오류 응답이다.
type APIError struct {
	Status int
	Body   map[string]any
}

func (e *APIError) Error() string {
	return fmt.Sprintf("HTTP %d %v", e.Status, e.Body)
}

func (c *client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		e := &APIError{Status: resp.StatusCode}
		_ = json.Unmarshal(raw, &e.Body)
		return e
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}
