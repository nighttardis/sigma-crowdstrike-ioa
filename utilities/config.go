package utilities

import (
	"fmt"
	"log"
	"os"

	"github.com/nighttardis/sigma_crowdstrike_ioa/auth"
	"gopkg.in/yaml.v3"
)

type HVaultAuth struct {
	VaultAddress        string `yaml:"vault_address"`
	VaultUsername       string `yaml:"username,omitempty"`
	VaultPassword       string `yaml:"password,omitempty"`
	VaultMountPath      string `yaml:"mount_path"`
	VaultKey            string `yaml:"key"`
	VaultCSClientID     string `yaml:"cs_client_id"`
	VaultCSClientSecret string `yaml:"cs_client_secret"`
}

type PlainTextAuth struct {
	CSClientID     string `yaml:"cs_client_id"`
	CSClientSecret string `yaml:"cs_client_secret"`
}

type Auth struct {
	AuthType  string        `yaml:"type"`
	HVault    HVaultAuth    `ymal:"hvault,omitempty"`
	PlainText PlainTextAuth `yaml:"plaintext,omitempty"`
}

type Config struct {
	Auth     Auth                         `yaml:"auth"`
	CSCloud  string                       `yaml:"cs_cloud"`
	Mappings map[string]map[string]string `yaml:"mapping"`
}

func LoadConfig(path string) *Config {
	f, err := os.ReadFile(path)

	if err != nil {
		log.Fatal(err)
	}

	var raw Config

	if err := yaml.Unmarshal(f, &raw); err != nil {
		log.Fatal(err)
	}

	return &raw
}

func (c Config) Authenticate() { //*client.CrowdStrikeAPISpecification {

	var cs_connect_info []string

	switch c.Auth.AuthType {
	case "hvault":
		cs_connect_info = auth.HashicorpVaultUser(c.Auth.HVault.VaultAddress, c.Auth.HVault.VaultUsername, c.Auth.HVault.VaultPassword, c.Auth.HVault.VaultMountPath, c.Auth.HVault.VaultKey, c.Auth.HVault.VaultCSClientID, c.Auth.HVault.VaultCSClientSecret)
	case "plaintext":
		cs_connect_info = []string{c.Auth.PlainText.CSClientID, c.Auth.PlainText.CSClientSecret}
	default:
		log.Fatalf("Unknown auth type %s", c.Auth.AuthType)
	}

	fmt.Println(cs_connect_info)

	// cs_client, err := falcon.NewClient(&falcon.ApiConfig{
	// 	ClientId:     cs_connect_info[0],
	// 	ClientSecret: cs_connect_info[1],
	// 	Context:      context.Background(),
	// 	Cloud:        falcon.Cloud(c.CSCloud),
	// })

	// if err != nil {
	// 	log.Print("Unable to connect to CrowdStrike")
	// 	log.Fatal(err)
	// }

	// return cs_client

}
