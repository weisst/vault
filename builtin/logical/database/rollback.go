package database

import (
	"context"
	"time"

	"github.com/hashicorp/vault/logical"
)

// walSetCredentials is used to store information in a WAL that can re-try a
// credential setting or rotation in the event of partial failure.
type walSetCredentials struct {
	Username          string    `json:"username"`
	NewPassword       string    `json:"new_password"`
	OldPassword       string    `json:"old_password"`
	RoleName          string    `json:"role_name"`
	Statements        []string  `json:"statements"`
	LastVaultRotation time.Time `json:"last_vault_rotation"`
}

func (b *databaseBackend) queueWALs(ctx context.Context, s logical.Storage) error {
	// list WALS

	// var entry walSetCredentials
	// // loop entries and examine
	// if err := mapstructure.Decode(data, &entry); err != nil {
	// 	return err
	// }
	// // check the LastVaultRotation times. If the role has had a password change
	// // since the wal's LastVaultRotation, we can assume things are fine here

	// // attempt to rollback the password to a known value

	return nil
}
