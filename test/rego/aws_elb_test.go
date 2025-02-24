package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/elb"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsElbTestCases)
}

var awsElbTestCases = testCases{
	"AVD-AWS-0053": {
		{
			name: "Load balancer publicly accessible",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						Internal: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer internally accessible",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						Internal: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0052": {
		{
			name: "Load balancer drop invalid headers disabled",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						Type:                    tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						DropInvalidHeaderFields: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer drop invalid headers enabled",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						Type:                    tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						DropInvalidHeaderFields: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Classic load balanace doesn't fail when no drop headers",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeClassic, tunnelTypes.NewTestMetadata()),
					},
				}}},
			},
			expected: false,
		},
	},
	"AVD-AWS-0054": {
		{
			name: "Load balancer listener with HTTP protocol",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTP", tunnelTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Type:     tunnelTypes.String("forward", tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener with HTTP protocol but redirect default action",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTP", tunnelTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Type:     tunnelTypes.String("redirect", tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTP protocol but redirect among multiple default actions",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTP", tunnelTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Type:     tunnelTypes.String("forward", tunnelTypes.NewTestMetadata()),
									},
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Type:     tunnelTypes.String("redirect", tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener with HTTPS protocol",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Type:     tunnelTypes.String(elb.TypeApplication, tunnelTypes.NewTestMetadata()),
						Listeners: []elb.Listener{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("HTTPS", tunnelTypes.NewTestMetadata()),
								DefaultActions: []elb.Action{
									{
										Metadata: tunnelTypes.NewTestMetadata(),
										Type:     tunnelTypes.String("forward", tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0047": {
		{
			name: "Load balancer listener using TLS v1.0",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								TLSPolicy: tunnelTypes.String("ELBSecurityPolicy-TLS-1-0-2015-04", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Load balancer listener using TLS v1.2",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								TLSPolicy: tunnelTypes.String("ELBSecurityPolicy-TLS-1-2-2017-01", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Load balancer listener using TLS v1.3",
			input: state.State{AWS: aws.AWS{ELB: elb.ELB{
				LoadBalancers: []elb.LoadBalancer{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Listeners: []elb.Listener{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								TLSPolicy: tunnelTypes.String("ELBSecurityPolicy-TLS13-1-2-2021-06", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
