package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud/computing"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(nifcloudComputingTestCases)
}

var nifcloudComputingTestCases = testCases{
	"AVD-NIF-0003": {
		{
			name: "NIFCLOUD security group rule has no description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD security group rule has description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								Description: tunnelTypes.String("some description", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0002": {
		{
			name: "NIFCLOUD security group with no description provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD security group with default description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("Managed by Terraform", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD security group with proper description",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("some proper description", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0004": {
		{
			name: "NIFCLOUD instance with no security group provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						SecurityGroup: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with security group",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						SecurityGroup: tunnelTypes.String("some security group", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0005": {
		{
			name: "NIFCLOUD instance with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								NetworkID: tunnelTypes.String("net-COMMON_PRIVATE", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD instance with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				Instances: []computing.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []computing.NetworkInterface{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								NetworkID: tunnelTypes.String("net-some-private-lan", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0001": {
		{
			name: "NIFCLOUD ingress security group rule with wildcard address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								CIDR:     tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD ingress security group rule with private address",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Computing: computing.Computing{
				SecurityGroups: []computing.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []computing.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								CIDR:     tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
