// Package config 는 YAML 설정 파일과 비밀 파일(Docker secret)을 읽는다(설계서 15절).
// 비밀 값은 설정 파일에 넣지 않고 *_file 경로로만 가리킨다.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Load 는 YAML 파일을 out 에 읽는다. 알 수 없는 키가 있으면 오류다.
func Load(path string, out any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("설정 파일 읽기: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(out); err != nil {
		return fmt.Errorf("설정 파일 해석(%s): %w", path, err)
	}
	return nil
}

// ReadSecret 은 비밀 파일 하나를 읽어 앞뒤 공백을 지운 값을 돌려준다. 값은 오류 메시지에도 넣지 않는다.
func ReadSecret(path string) (string, error) {
	if path == "" {
		return "", errors.New("비밀 파일 경로가 비었다")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("비밀 파일 읽기(%s): %w", path, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("비밀 파일이 비었다(%s)", path)
	}
	return v, nil
}
