package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud/nas"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(nifcloudNasTestCases)
}

var nifcloudNasTestCases = testCases{
	"AVD-NIF-0015": {
		{
			name: "NIFCLOUD nas security group with no description provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with default description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("Managed by Terraform", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD nas security group with proper description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("some proper description", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0013": {
		{
			name: "NIFCLOUD nas instance with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						NetworkID: tunnelTypes.String("net-COMMON_PRIVATE", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD nas instance with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASInstances: []nas.NASInstance{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						NetworkID: tunnelTypes.String("net-some-private-lan", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0014": {
		{
			name: "NIFCLOUD ingress nas security group rule with wildcard address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						CIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress nas security group rule with private address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{NAS: nas.NAS{
				NASSecurityGroups: []nas.NASSecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						CIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
