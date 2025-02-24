package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/openstack"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(openStackTestCases)
}

var openStackTestCases = testCases{
	"AVD-OPNSTK-0001": {
		{
			name: "Instance admin with plaintext password set",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Instances: []openstack.Instance{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						AdminPassword: tunnelTypes.String("very-secret", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance admin with no plaintext password",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Instances: []openstack.Instance{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						AdminPassword: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-OPNSTK-0002": {
		{
			name: "Firewall rule missing destination address",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    tunnelTypes.NewTestMetadata(),
							Enabled:     tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Destination: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							Source:      tunnelTypes.String("10.10.10.1", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall rule missing source address",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    tunnelTypes.NewTestMetadata(),
							Enabled:     tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Destination: tunnelTypes.String("10.10.10.2", tunnelTypes.NewTestMetadata()),
							Source:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall rule with public destination and source addresses",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    tunnelTypes.NewTestMetadata(),
							Enabled:     tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Destination: tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
							Source:      tunnelTypes.String("0.0.0.0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall rule with private destination and source addresses",
			input: state.State{OpenStack: openstack.OpenStack{Compute: openstack.Compute{
				Firewall: openstack.Firewall{
					AllowRules: []openstack.FirewallRule{
						{
							Metadata:    tunnelTypes.NewTestMetadata(),
							Enabled:     tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Destination: tunnelTypes.String("10.10.10.1", tunnelTypes.NewTestMetadata()),
							Source:      tunnelTypes.String("10.10.10.2", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-OPNSTK-0005": {
		{
			name: "Security group missing description",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group with description",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("this is for connecting to the database", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-OPNSTK-0004": {
		{
			name: "Security group rule missing address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("10.10.0.1", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("8.8.8.8", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("80.0.0.0/8", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-OPNSTK-0003": {
		{
			name: "Security group rule missing address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with private address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("10.10.0.1", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with single public address",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("8.8.8.8", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule with large public cidr",
			input: state.State{OpenStack: openstack.OpenStack{Networking: openstack.Networking{
				SecurityGroups: []openstack.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []openstack.SecurityGroupRule{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsIngress: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CIDR:      tunnelTypes.String("80.0.0.0/8", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
