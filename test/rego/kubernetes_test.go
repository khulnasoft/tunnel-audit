package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/kubernetes"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(kubernetesTestCases)
}

var kubernetesTestCases = testCases{
	"AVD-KUBE-0001": []testCase{
		{
			name: "Public source CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Ingress: kubernetes.Ingress{
								Metadata: tunnelTypes.NewTestMetadata(),
								SourceCIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "Private source CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Ingress: kubernetes.Ingress{
								Metadata: tunnelTypes.NewTestMetadata(),
								SourceCIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
	},
	"AVD-KUBE-0002": []testCase{
		{
			name: "Public destination CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Egress: kubernetes.Egress{
								Metadata: tunnelTypes.NewTestMetadata(),
								DestinationCIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "Private destination CIDR",
			input: state.State{Kubernetes: kubernetes.Kubernetes{
				NetworkPolicies: []kubernetes.NetworkPolicy{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Spec: kubernetes.NetworkPolicySpec{
							Metadata: tunnelTypes.NewTestMetadata(),
							Egress: kubernetes.Egress{
								Metadata: tunnelTypes.NewTestMetadata(),
								DestinationCIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
	},
}
