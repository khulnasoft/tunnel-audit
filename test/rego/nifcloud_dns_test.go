package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud/dns"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(nifcloudDnsTestCases)
}

var nifcloudDnsTestCases = testCases{
	"AVD-NIF-0007": {
		{
			name:     "No records",
			input:    state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{}}},
			expected: false,
		},
		{
			name: "Some record",
			input: state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String("A", tunnelTypes.NewTestMetadata()),
						Record:   tunnelTypes.String("some", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Some TXT record",
			input: state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String("TXT", tunnelTypes.NewTestMetadata()),
						Record:   tunnelTypes.String("some", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},

		{
			name: "Verify TXT record",
			input: state.State{Nifcloud: nifcloud.Nifcloud{DNS: dns.DNS{
				Records: []dns.Record{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String("TXT", tunnelTypes.NewTestMetadata()),
						Record:   tunnelTypes.String(dns.ZoneRegistrationAuthTxt, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
}
