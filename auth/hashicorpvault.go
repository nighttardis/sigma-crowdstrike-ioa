package auth

import (
	"context"
	"log"
	"time"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

func HashicorpVaultUser(vaultAddress string, userName string, passsWord string, mountPath string, vaultKey string, client_id_secret string, client_secret_secret string) []string {

	ctx := context.Background()

	client, err := vault.New(
		vault.WithAddress(vaultAddress),
		vault.WithRequestTimeout(30*time.Second),
	)

	if err != nil {
		log.Print("Error Creating Vault Connection")
		log.Fatal(err)
	}

	resp, err := client.Auth.UserpassLogin(
		ctx,
		userName,
		schema.UserpassLoginRequest{
			Password: passsWord,
		},
	)

	if err != nil {
		log.Print("Error Authing")
		log.Fatal(err)
	}

	if err := client.SetToken(resp.Auth.ClientToken); err != nil {
		log.Fatal(err)
	}

	client_id, err := client.Secrets.KvV2Read(
		ctx,
		vaultKey,
		vault.WithMountPath(mountPath),
	)

	if err != nil {
		log.Println("Unable to find key")
		log.Fatal(err)
	}

	if !(slices.Contains(maps.Keys(client_id.Data.Data), client_id_secret) && slices.Contains(maps.Keys(client_id.Data.Data), client_secret_secret)) {
		log.Fatalf("Unable to find one or both of %s or %s from provided Hashicorp configuration", client_id_secret, client_secret_secret)
	}

	return []string{client_id.Data.Data[client_id_secret].(string), client_id.Data.Data[client_secret_secret].(string)}
}
