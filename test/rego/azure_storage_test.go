package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/storage"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureStorageTestCases)
}

var azureStorageTestCases = testCases{
	"AVD-AZU-0010": {
		{
			name: "Azure storage rule doesn't allow bypass access",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Bypass:   []tunnelTypes.StringValue{},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Azure storage rule allows bypass access to Microsoft services",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Bypass: []tunnelTypes.StringValue{
									tunnelTypes.String("AzureServices", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0012": {
		{
			name: "Storage network rule allows access by default",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								AllowByDefault: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage network rule denies access by default",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								AllowByDefault: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0008": {
		{
			name: "Storage account HTTPS enforcement disabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						EnforceHTTPS: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account HTTPS enforcement enabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						EnforceHTTPS: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0007": {
		{
			name: "Storage account container public access set to blob",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								PublicAccess: tunnelTypes.String(storage.PublicAccessBlob, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account container public access set to container",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								PublicAccess: tunnelTypes.String(storage.PublicAccessContainer, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account container public access set to off",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Containers: []storage.Container{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								PublicAccess: tunnelTypes.String(storage.PublicAccessOff, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0009": {
		{
			name: "Storage account queue properties logging disabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      tunnelTypes.NewTestMetadata(),
							EnableLogging: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
						Queues: []storage.Queue{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Name:     tunnelTypes.String("my-queue", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account queue properties logging disabled with no queues",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      tunnelTypes.NewTestMetadata(),
							EnableLogging: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Storage account queue properties logging enabled",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      tunnelTypes.NewTestMetadata(),
							EnableLogging: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0011": {
		{
			name: "Storage account minimum TLS version unspecified",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account minimum TLS version 1.0",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						MinimumTLSVersion: tunnelTypes.String("TLS1_0", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Storage account minimum TLS version 1.2",
			input: state.State{Azure: azure.Azure{Storage: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						MinimumTLSVersion: tunnelTypes.String("TLS1_2", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
