package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/network"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureNetworkTestCases)
}

var azureNetworkTestCases = testCases{
	"AVD-AZU-0048": {
		{
			name: "Security group inbound rule allowing RDP access from the Internet",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(3310),
										End:      tunnelTypes.IntTest(3390),
									},
								},
								Protocol: tunnelTypes.String("Tcp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group inbound rule allowing RDP access from a specific address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(3310),
										End:      tunnelTypes.IntTest(3390),
									},
								},
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("4.53.160.75", tunnelTypes.NewTestMetadata()),
								},
								Protocol: tunnelTypes.String("Tcp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group inbound rule allowing only ICMP",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(3310),
										End:      tunnelTypes.IntTest(3390),
									},
								},
								Protocol: tunnelTypes.String("Icmp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group inbound rule allowing non RDP access from public internet",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
								SourcePorts:          nil,
								DestinationAddresses: nil,
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(8080),
										End:      tunnelTypes.IntTest(8080),
									},
								},
								Protocol: tunnelTypes.String("Tcp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0051": {
		{
			name: "Security group outbound rule with wildcard destination address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								DestinationAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group outbound rule with private destination address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								DestinationAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0047": {
		{
			name: "Security group inbound rule with wildcard source address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group inbound rule with private source address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0049": {
		{
			name: "Network watcher flow log retention policy disabled",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							Days:     tunnelTypes.Int(100, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 30 days",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Days:     tunnelTypes.Int(30, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network watcher flow log retention policy enabled for 100 days",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Days:     tunnelTypes.Int(100, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0050": {
		{
			name: "Security group rule allowing SSH access from the public internet",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(22),
										End:      tunnelTypes.IntTest(22),
									},
								},
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
								Protocol: tunnelTypes.String("Tcp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security group rule allowing SSH only ICMP",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(22),
										End:      tunnelTypes.IntTest(22),
									},
								},
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("*", tunnelTypes.NewTestMetadata()),
								},
								Protocol: tunnelTypes.String("Icmp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule allowing non SSH access from the public internet",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(8080),
										End:      tunnelTypes.IntTest(8080),
									},
								},
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("82.102.23.23", tunnelTypes.NewTestMetadata()),
								},
								Protocol: tunnelTypes.String("Tcp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Security group rule allowing SSH access from a specific address",
			input: state.State{Azure: azure.Azure{Network: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Allow:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Outbound: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								DestinationPorts: []network.PortRange{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Start:    tunnelTypes.IntTest(22),
										End:      tunnelTypes.IntTest(22),
									},
								},
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("82.102.23.23", tunnelTypes.NewTestMetadata()),
								},
								Protocol: tunnelTypes.String("Tcp", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
