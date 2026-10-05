// go run .   (module replace points at ../../clients/go)
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	vault "github.com/aps-vault/aps-vault/clients/go"
)

func main() {
	v, err := vault.FromEnv() // VAULT_URL + VAULT_TOKEN / VAULT_TOKEN_FILE
	if err != nil {
		fmt.Fprintln(os.Stderr, "config error:", err)
		os.Exit(2)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	db, err := v.GetFull(ctx, "db-password")
	if err != nil {
		var ve *vault.Error
		if errors.As(err, &ve) {
			fmt.Fprintf(os.Stderr, "vault refused: HTTP %d\n", ve.Status) // 404 = not in this folder, 401 = token revoked
		} else {
			fmt.Fprintln(os.Stderr, "vault unreachable:", err)
		}
		os.Exit(1)
	}
	fmt.Printf("connecting as %s, password length %d\n", db.Login, len(db.Value))
}
