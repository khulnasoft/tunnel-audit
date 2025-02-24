package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/nifcloud/network"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(nifcloudNetworkTestCases)
}

var nifcloudNetworkTestCases = testCases{
	"AVD-NIF-0016": {
		{
			name: "NIFCLOUD router with no security group provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						SecurityGroup: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD router with security group",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						SecurityGroup: tunnelTypes.String("some security group", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0018": {
		{
			name: "NIFCLOUD vpnGateway with no security group provided",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				VpnGateways: []network.VpnGateway{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						SecurityGroup: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "NIFCLOUD vpnGateway with security group",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				VpnGateways: []network.VpnGateway{
					{
						Metadata:      tunnelTypes.NewTestMetadata(),
						SecurityGroup: tunnelTypes.String("some security group", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0021": {
		{
			name: "Elastic Load balancer listener with HTTP protocol on global",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     tunnelTypes.NewTestMetadata(),
							NetworkID:    tunnelTypes.String("net-COMMON_GLOBAL", tunnelTypes.NewTestMetadata()),
							IsVipNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTP", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Elastic Load balancer listener with HTTP protocol on internal",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     tunnelTypes.NewTestMetadata(),
							NetworkID:    tunnelTypes.String("some-network", tunnelTypes.NewTestMetadata()),
							IsVipNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTP", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Elastic Load balancer listener with HTTPS protocol on global",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{{
							Metadata:     tunnelTypes.NewTestMetadata(),
							NetworkID:    tunnelTypes.String("net-COMMON_GLOBAL", tunnelTypes.NewTestMetadata()),
							IsVipNetwork: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						}},
						Listeners: []network.ElasticLoadBalancerListener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTPS", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTP", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTPS", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-NIF-0019": {
		{
			name: "NIFCLOUD elb with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
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
			name: "NIFCLOUD elb with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				ElasticLoadBalancers: []network.ElasticLoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
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
	"AVD-NIF-0017": {
		{
			name: "NIFCLOUD router with common private",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
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
			name: "NIFCLOUD router with private LAN",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				Routers: []network.Router{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []network.NetworkInterface{
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
	"AVD-NIF-0020": {
		{
			name: "Load balancer listener using TLS v1.0",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								TLSPolicy: tunnelTypes.String("Standard Ciphers A ver1", tunnelTypes.NewTestMetadata()),
								Protocol:  tunnelTypes.String("HTTPS", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								TLSPolicy: tunnelTypes.String("Standard Ciphers D ver1", tunnelTypes.NewTestMetadata()),
								Protocol:  tunnelTypes.String("HTTPS", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener using ICMP",
			input: state.State{Nifcloud: nifcloud.Nifcloud{Network: network.Network{
				LoadBalancers: []network.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []network.LoadBalancerListener{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								TLSPolicy: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
								Protocol:  tunnelTypes.String("ICMP", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
