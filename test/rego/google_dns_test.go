package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/dns"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleDnsTestCases)
}

var googleDnsTestCases = testCases{
	"AVD-GCP-0013": {
		{
			name: "DNSSec disabled and required when visibility explicitly public",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Visibility: tunnelTypes.String("public", tunnelTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DNSSec enabled",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Visibility: tunnelTypes.String("public", tunnelTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "DNSSec not required when private",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Visibility: tunnelTypes.String("private", tunnelTypes.NewTestMetadata()),
						DNSSec: dns.DNSSec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0012": {
		{
			name: "Zone signing using RSA SHA1 key",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: tunnelTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  tunnelTypes.NewTestMetadata(),
									Algorithm: tunnelTypes.String("rsasha1", tunnelTypes.NewTestMetadata()),
									KeyType:   tunnelTypes.String("keySigning", tunnelTypes.NewTestMetadata()),
								},
								{
									Metadata:  tunnelTypes.NewTestMetadata(),
									Algorithm: tunnelTypes.String("rsasha1", tunnelTypes.NewTestMetadata()),
									KeyType:   tunnelTypes.String("zoneSigning", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Zone signing using RSA SHA512 key",
			input: state.State{Google: google.Google{DNS: dns.DNS{
				ManagedZones: []dns.ManagedZone{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DNSSec: dns.DNSSec{
							Metadata: tunnelTypes.NewTestMetadata(),
							DefaultKeySpecs: []dns.KeySpecs{
								{
									Metadata:  tunnelTypes.NewTestMetadata(),
									Algorithm: tunnelTypes.String("rsasha512", tunnelTypes.NewTestMetadata()),
									KeyType:   tunnelTypes.String("keySigning", tunnelTypes.NewTestMetadata()),
								},
								{
									Metadata:  tunnelTypes.NewTestMetadata(),
									Algorithm: tunnelTypes.String("rsasha512", tunnelTypes.NewTestMetadata()),
									KeyType:   tunnelTypes.String("zoneSigning", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
