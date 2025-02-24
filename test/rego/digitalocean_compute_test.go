package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/digitalocean"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/digitalocean/compute"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(digitalOceanTestCases)
}

var digitalOceanTestCases = testCases{
	"AVD-DIG-0008": {
		{
			name: "Kubernetes cluster auto-upgrade disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						AutoUpgrade: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Kubernetes cluster auto-upgrade enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						AutoUpgrade: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0002": {
		{
			name: "Load balancer forwarding rule using HTTP",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      tunnelTypes.NewTestMetadata(),
								EntryProtocol: tunnelTypes.String("http", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer forwarding rule using HTTPS",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      tunnelTypes.NewTestMetadata(),
								EntryProtocol: tunnelTypes.String("https", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer forwarding rule using HTTP, but HTTP redirection to HTTPS is enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				LoadBalancers: []compute.LoadBalancer{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						RedirectHttpToHttps: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						ForwardingRules: []compute.ForwardingRule{
							{
								Metadata:      tunnelTypes.NewTestMetadata(),
								EntryProtocol: tunnelTypes.String("http", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0005": {
		{
			name: "Kubernetes cluster surge upgrade disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						SurgeUpgrade: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Kubernetes cluster surge upgrade enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				KubernetesClusters: []compute.KubernetesCluster{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						SurgeUpgrade: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0003": {
		{
			name: "Firewall outbound rule with multiple public destination addresses",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								DestinationAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
									tunnelTypes.String("::/0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall outbound rule with a private destination address",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						OutboundRules: []compute.OutboundFirewallRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								DestinationAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("192.168.1.0/24", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0001": {
		{
			name: "Firewall inbound rule with multiple public source addresses",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
									tunnelTypes.String("::/0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Firewall inbound rule with a private source address",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Firewalls: []compute.Firewall{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						InboundRules: []compute.InboundFirewallRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								SourceAddresses: []tunnelTypes.StringValue{
									tunnelTypes.String("192.168.1.0/24", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0004": {
		{
			name: "Droplet missing SSH keys",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Droplets: []compute.Droplet{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SSHKeys:  []tunnelTypes.StringValue{},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Droplet with an SSH key provided",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Compute: compute.Compute{
				Droplets: []compute.Droplet{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SSHKeys: []tunnelTypes.StringValue{
							tunnelTypes.String("my-ssh-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
