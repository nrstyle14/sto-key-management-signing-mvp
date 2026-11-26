//go:build !signtx_m1

package main

import "net/http"

// 기본 빌드에는 서명 API 가 없다. M1 단계의 서명 API 는 정책·승인 검사(5.3의 5·6단계)가 빠져 있어
// 통합 시험용 빌드 태그(signtx_m1)로만 연다(작업지시서 T1.5). T2.4 에서 태그를 없앤다.
func registerSignRoutes(_ *app, _ *http.ServeMux) {}
