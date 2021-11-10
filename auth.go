package vk

import (
	"context"

	"github.com/hashicorp/vault/api"
)

// AppRole implements AppRole authentication with Vault.
type AppRole struct {
	// Path is the full login path for the current AppRole. Defaults to auth/approle/login if used in CLI.
	Path string
	// RoleID & SecretID are the login credentials sent to Vault in the Login call.
	RoleID   string `mapstructure:"role_id"`
	SecretID string `mapstructure:"secret_id"`
}

func (approle *AppRole) Validate() bool {
	return approle.Path != "" && approle.RoleID != "" && approle.SecretID != ""
}

// Login makes an attempt to log in to Vault with the current AppRole.
func (approle *AppRole) Login(_ context.Context, client *api.Client) (*api.Secret, error) {
	return client.Logical().Write(approle.Path, map[string]interface{}{
		"role_id":   approle.RoleID,
		"secret_id": approle.SecretID,
	})
}

// Userpass implements userpass authentication with Vault.
type Userpass struct {
	// Path is the full login path. Looks something like auth/userpass/users/Cassandra
	Path string
	// Password is the login credential to be used with Login.
	Password string
}

func (userpass *Userpass) Validate() bool {
	return userpass.Path != "" && userpass.Password != ""
}

// Login implements the vault AuthMethod for userpass.
func (userpass *Userpass) Login(_ context.Context, client *api.Client) (*api.Secret, error) {
	return client.Logical().Write(userpass.Path, map[string]interface{}{
		"password": userpass.Password,
	})
}
