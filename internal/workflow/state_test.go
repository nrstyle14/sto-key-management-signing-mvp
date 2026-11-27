package workflow

import "testing"

func TestTransitions(t *testing.T) {
	ok := [][2]Status{
		{StatusDraft, StatusPendingApproval}, {StatusPendingApproval, StatusApproved}, {StatusPendingApproval, StatusRejected},
		{StatusPendingApproval, StatusExpired}, {StatusApproved, StatusSigned}, {StatusApproved, StatusFailed},
		{StatusApproved, StatusExpired}, {StatusSigned, StatusSubmitted}, {StatusSigned, StatusFailed}, {StatusSubmitted, StatusConfirmed}, {StatusSubmitted, StatusFailed},
	}
	for _, p := range ok {
		if !CanTransition(p[0], p[1]) {
			t.Errorf("%s → %s 가 막혔다", p[0], p[1])
		}
	}
	bad := [][2]Status{
		{StatusPendingApproval, StatusSigned}, {StatusRejected, StatusApproved}, {StatusExpired, StatusApproved},
		{StatusSigned, StatusApproved}, {StatusConfirmed, StatusFailed}, {StatusFailed, StatusApproved}, {StatusApproved, StatusPendingApproval},
	}
	for _, p := range bad {
		if CanTransition(p[0], p[1]) {
			t.Errorf("%s → %s 가 허용됐다", p[0], p[1])
		}
	}
}
