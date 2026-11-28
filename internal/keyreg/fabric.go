package keyreg

import (
	"context"
	"database/sql"
	"time"

	"github.com/da-infra/sto-key-management-signing-mvp/internal/store"
)

// Fabric 신원 상태(설계서 10.5, D-26)
const (
	IdentityEnrolled = "ENROLLED"
	IdentityRevoked  = "REVOKED"
)

// Identity 는 Fabric 신원 기록이다.
type Identity struct {
	KeyID        string     `json:"key_id"`
	MSPID        string     `json:"msp_id"`
	EnrollmentID string     `json:"enrollment_id"`
	CertPEM      string     `json:"cert_pem"`
	Serial       string     `json:"serial"`
	AKI          string     `json:"aki"`
	NotAfter     time.Time  `json:"not_after"`
	Status       string     `json:"status"`
	RevokedAt    *time.Time `json:"revoked_at,omitempty"`
}

// GetIdentity 는 키의 Fabric 신원이다.
func GetIdentity(ctx context.Context, db store.DBTX, keyID string) (*Identity, error) {
	var i Identity
	var revoked sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT key_id, msp_id, enrollment_id, cert_pem, serial, aki, not_after, status, revoked_at
		FROM fabric_identities WHERE key_id = ?`, keyID).Scan(&i.KeyID, &i.MSPID, &i.EnrollmentID, &i.CertPEM, &i.Serial, &i.AKI, &i.NotAfter, &i.Status, &revoked)
	if err != nil {
		return nil, err
	}
	if revoked.Valid {
		t := revoked.Time.UTC()
		i.RevokedAt = &t
	}
	i.NotAfter = i.NotAfter.UTC()
	return &i, nil
}
