/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"gocloud.dev/runtimevar"

	// Side-effect imports register runtimevar drivers so URLs whose
	// scheme is one of these resolve without callers having to wire
	// the driver themselves. Add a driver here when broadening
	// non-Azure cloud coverage.
	_ "gocloud.dev/runtimevar/awsparamstore"
	_ "gocloud.dev/runtimevar/awssecretsmanager"
	_ "gocloud.dev/runtimevar/filevar"
	_ "gocloud.dev/runtimevar/gcpsecretmanager"
)

// URLProvider fetches mnemonics from one or more cloud secret backends,
// addressed by URL. Each URL's scheme picks the backend:
//
//	awssecretsmanager://<arn>?region=us-east-1                   → AWS Secrets Manager
//	awsparamstore://<path>?region=us-east-1                      → AWS SSM Parameter Store
//	gcpsecretmanager://projects/PROJECT/secrets/NAME/versions/V  → GCP Secret Manager
//	azurekeyvault://<vault>/<secret>                             → Azure Key Vault
//	file:///absolute/path/to/mnemonic                            → local file (tests / dev)
//
// Implementation note: AWS / GCP / file URLs route through
// gocloud.dev/runtimevar, which is the actual cross-cloud abstraction.
// Azure has no runtimevar driver — gocloud.dev/secrets/azurekeyvault
// is a KMS encrypt/decrypt API, not a secret-fetch API — so Azure URLs
// route through azsecrets directly. The carve-out is hidden inside
// this provider; consumers see one uniform "give me a URL, get a
// mnemonic" surface.
type URLProvider struct {
	// URLs maps logical name → backend URL. The name labels logs and
	// error messages; lookups in the assembled keystore are still by
	// derived address.
	URLs map[string]string

	// AzureCredential, when non-nil, is used for any azurekeyvault://
	// URLs. Nil means "construct via azidentity.NewDefaultAzureCredential
	// on first use" (managed identity → env vars → CLI in that order).
	// Tests inject a fake credential here.
	AzureCredential azcore.TokenCredential
}

// NewURLProviderFromEnv parses an env-var of the form
// "name1=url1,name2=url2" into a URLProvider. Whitespace around names
// and URLs is trimmed. Returns nil when the env var is empty or no
// pair parses, so callers can pass the result directly to KeyStore.New
// without nil-checking.
//
// Convention used by node + proxy main.go:
//
//	ZS_MNEMONIC_URLS=signing=awssecretsmanager://...,payment=gcpsecretmanager://...,backup=azurekeyvault://VAULT/SECRET
func NewURLProviderFromEnv(envVarValue string) *URLProvider {
	v := strings.TrimSpace(envVarValue)
	if v == "" {
		return nil
	}
	urls := map[string]string{}
	for _, pair := range strings.Split(v, ",") {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}
		eq := strings.IndexByte(pair, '=')
		if eq <= 0 {
			continue
		}
		name := strings.TrimSpace(pair[:eq])
		url := strings.TrimSpace(pair[eq+1:])
		if name == "" || url == "" {
			continue
		}
		urls[name] = url
	}
	if len(urls) == 0 {
		return nil
	}
	return &URLProvider{URLs: urls}
}

const azureKeyVaultScheme = "azurekeyvault://"

// Mnemonics fetches every configured URL and returns the values as
// MnemonicEntry. A failure on any single URL aborts the whole load —
// partial keystores would mask misconfiguration of one source while
// pretending the others are sufficient.
func (p *URLProvider) Mnemonics(ctx context.Context) ([]MnemonicEntry, error) {
	if p == nil || len(p.URLs) == 0 {
		return nil, nil
	}

	// Lazily resolve the Azure credential so callers without any Azure
	// URLs never trigger azidentity's managed-identity probe.
	var (
		azCred     azcore.TokenCredential
		azCredOnce sync.Once
		azCredErr  error
	)
	resolveAzCred := func() (azcore.TokenCredential, error) {
		azCredOnce.Do(func() {
			if p.AzureCredential != nil {
				azCred = p.AzureCredential
				return
			}
			azCred, azCredErr = azidentity.NewDefaultAzureCredential(nil)
		})
		return azCred, azCredErr
	}

	out := make([]MnemonicEntry, 0, len(p.URLs))
	for name, url := range p.URLs {
		var (
			mn  string
			err error
		)
		switch {
		case strings.HasPrefix(url, azureKeyVaultScheme):
			cred, credErr := resolveAzCred()
			if credErr != nil {
				return nil, fmt.Errorf("urlprovider: azure credential: %w", credErr)
			}
			mn, err = fetchAzureKeyVault(ctx, cred, url)
		default:
			mn, err = fetchGoCloud(ctx, url)
		}
		if err != nil {
			return nil, fmt.Errorf("urlprovider: %s (%s): %w", name, url, err)
		}
		out = append(out, MnemonicEntry{Name: name, Mnemonic: strings.TrimSpace(mn)})
	}
	return out, nil
}

// fetchGoCloud opens a runtimevar URL, reads the latest snapshot, and
// returns its string value. The variable is closed before the value
// is returned so we don't leak the underlying client when this is
// called many times in a loop.
func fetchGoCloud(ctx context.Context, url string) (string, error) {
	v, err := runtimevar.OpenVariable(ctx, url)
	if err != nil {
		return "", fmt.Errorf("open: %w", err)
	}
	snap, err := v.Latest(ctx)
	closeErr := v.Close()
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close: %w", closeErr)
	}
	// runtimevar's default decoder is bytes (filevar, awsparamstore, etc.);
	// the string decoder is opt-in via ?decoder=string. Accept both so
	// callers don't have to remember to tack the query param on.
	switch v := snap.Value.(type) {
	case string:
		return v, nil
	case []byte:
		return string(v), nil
	default:
		return "", fmt.Errorf("got %T, want string or []byte", snap.Value)
	}
}

// fetchAzureKeyVault reads a single secret from Azure Key Vault. Empty
// version selects "latest".
func fetchAzureKeyVault(ctx context.Context, cred azcore.TokenCredential, url string) (string, error) {
	vault, name, err := parseAzureKeyVaultURL(url)
	if err != nil {
		return "", err
	}
	client, err := azsecrets.NewClient(vault, cred, nil)
	if err != nil {
		return "", fmt.Errorf("client for %s: %w", vault, err)
	}
	resp, err := client.GetSecret(ctx, name, "", nil)
	if err != nil {
		return "", fmt.Errorf("get %s/%s: %w", vault, name, err)
	}
	if resp.Value == nil {
		return "", fmt.Errorf("%s/%s: secret has no value", vault, name)
	}
	return *resp.Value, nil
}

// parseAzureKeyVaultURL turns "azurekeyvault://my-vault/my-secret" into
// ("https://my-vault.vault.azure.net/", "my-secret"). The vault DNS
// suffix is hard-coded to the public Azure cloud. Tests bypass by
// injecting an AzureCredential and a pre-resolved client via the
// fetchAzureKeyVault internals.
func parseAzureKeyVaultURL(url string) (vaultURL, secretName string, err error) {
	if !strings.HasPrefix(url, azureKeyVaultScheme) {
		return "", "", fmt.Errorf("expected scheme %q, got %q", azureKeyVaultScheme, url)
	}
	rest := strings.TrimPrefix(url, azureKeyVaultScheme)
	slash := strings.IndexByte(rest, '/')
	if slash <= 0 || slash == len(rest)-1 {
		return "", "", fmt.Errorf("expected azurekeyvault://VAULT/SECRET, got %q", url)
	}
	vault := rest[:slash]
	name := rest[slash+1:]
	return fmt.Sprintf("https://%s.vault.azure.net/", vault), name, nil
}
