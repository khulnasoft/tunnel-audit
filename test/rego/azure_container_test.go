package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/container"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureContainerTestCases)
}

var azureContainerTestCases = testCases{
	"AVD-AZU-0043": {
		{
			name: "Cluster missing network policy configuration",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      tunnelTypes.NewTestMetadata(),
							NetworkPolicy: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with network policy configured",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkProfile: container.NetworkProfile{
							Metadata:      tunnelTypes.NewTestMetadata(),
							NetworkPolicy: tunnelTypes.String("calico", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0041": {
		{
			name: "API server authorized IP ranges undefined",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:                    tunnelTypes.NewTestMetadata(),
						EnablePrivateCluster:        tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []tunnelTypes.StringValue{},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API server authorized IP ranges defined",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata:             tunnelTypes.NewTestMetadata(),
						EnablePrivateCluster: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						APIServerAuthorizedIPRanges: []tunnelTypes.StringValue{
							tunnelTypes.String("1.2.3.4/32", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0040": {
		{
			name: "Logging via OMS agent disabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: tunnelTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Logging via OMS agent enabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AddonProfile: container.AddonProfile{
							Metadata: tunnelTypes.NewTestMetadata(),
							OMSAgent: container.OMSAgent{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0042": {
		{
			name: "Role based access control disabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Role based access control enabled",
			input: state.State{Azure: azure.Azure{Container: container.Container{
				KubernetesClusters: []container.KubernetesCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RoleBasedAccessControl: container.RoleBasedAccessControl{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
