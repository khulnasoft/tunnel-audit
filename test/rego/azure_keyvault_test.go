package test

import (
	"time"

	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/keyvault"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureKeyVaultTestCases)
}

var azureKeyVaultTestCases = testCases{
	"AVD-AZU-0015": {
		{
			name: "Key vault secret content-type not specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								ContentType: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Key vault secret content-type specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								ContentType: tunnelTypes.String("password", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0014": {
		{
			name: "Key vault key expiration date not set",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Keys: []keyvault.Key{
							{
								Metadata:   tunnelTypes.NewTestMetadata(),
								ExpiryDate: tunnelTypes.Time(time.Time{}, tunnelTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Key vault key expiration date specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Keys: []keyvault.Key{
							{
								Metadata:   tunnelTypes.NewTestMetadata(),
								ExpiryDate: tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0017": {
		{
			name: "Key vault secret expiration date not set",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   tunnelTypes.NewTestMetadata(),
								ExpiryDate: tunnelTypes.Time(time.Time{}, tunnelTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Key vault secret expiration date specified",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   tunnelTypes.NewTestMetadata(),
								ExpiryDate: tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0016": {
		{
			name: "Keyvault purge protection disabled",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						EnablePurgeProtection:   tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: tunnelTypes.Int(30, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled but soft delete retention period set to 3 days",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						EnablePurgeProtection:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: tunnelTypes.Int(3, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled and soft delete retention period set to 30 days",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						EnablePurgeProtection:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						SoftDeleteRetentionDays: tunnelTypes.Int(30, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0013": {
		{
			name: "Network ACL default action set to allow",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      tunnelTypes.NewTestMetadata(),
							DefaultAction: tunnelTypes.String("Allow", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network ACL default action set to deny",
			input: state.State{Azure: azure.Azure{KeyVault: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      tunnelTypes.NewTestMetadata(),
							DefaultAction: tunnelTypes.String("Deny", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
