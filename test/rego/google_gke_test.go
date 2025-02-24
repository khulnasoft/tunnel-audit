package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/gke"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleGkeTestCases)
}

var googleGkeTestCases = testCases{
	"AVD-GCP-0063": {
		{
			name: "Node pool auto repair disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         tunnelTypes.NewTestMetadata(),
									EnableAutoRepair: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Node pool auto repair enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:         tunnelTypes.NewTestMetadata(),
									EnableAutoRepair: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0058": {
		{
			name: "Node pool auto upgrade disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          tunnelTypes.NewTestMetadata(),
									EnableAutoUpgrade: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Node pool auto upgrade enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Management: gke.Management{
									Metadata:          tunnelTypes.NewTestMetadata(),
									EnableAutoUpgrade: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0049": {
		{
			name: "Cluster IP aliasing disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster IP aliasing enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IPAllocationPolicy: gke.IPAllocationPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0061": {
		{
			name: "Cluster master authorized networks disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster master authorized networks enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0056": {
		{
			name: "Cluster network policy disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster network policy enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster autopilot enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
						EnableAutpilot: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Dataplane v2 enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkPolicy: gke.NetworkPolicy{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
						DatapathProvider: tunnelTypes.String("ADVANCED_DATAPATH", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0059": {
		{
			name: "Cluster private nodes disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PrivateCluster: gke.PrivateCluster{
							Metadata:           tunnelTypes.NewTestMetadata(),
							EnablePrivateNodes: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster private nodes enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PrivateCluster: gke.PrivateCluster{
							Metadata:           tunnelTypes.NewTestMetadata(),
							EnablePrivateNodes: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0060": {
		{
			name: "Cluster missing logging service provider",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						LoggingService: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with StackDriver logging configured",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						LoggingService: tunnelTypes.String("logging.googleapis.com/kubernetes", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0052": {
		{
			name: "Cluster missing monitoring service provider",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						MonitoringService: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with StackDriver monitoring configured",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						MonitoringService: tunnelTypes.String("monitoring.googleapis.com/kubernetes", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0048": {
		{
			name: "Cluster legacy metadata endpoints enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              tunnelTypes.NewTestMetadata(),
							EnableLegacyEndpoints: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster legacy metadata endpoints disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              tunnelTypes.NewTestMetadata(),
							EnableLegacyEndpoints: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints disabled on non-default node pool",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              tunnelTypes.NewTestMetadata(),
							EnableLegacyEndpoints: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster legacy metadata endpoints enabled on non-default node pool",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:              tunnelTypes.NewTestMetadata(),
							EnableLegacyEndpoints: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
						RemoveDefaultNodePool: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									EnableLegacyEndpoints: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-GCP-0064": {
		{
			name: "Cluster master authentication by certificate",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: tunnelTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         tunnelTypes.NewTestMetadata(),
								IssueCertificate: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster master authentication by username/password",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: tunnelTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         tunnelTypes.NewTestMetadata(),
								IssueCertificate: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
							Username: tunnelTypes.String("username", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster master authentication by certificate or username/password disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuth: gke.MasterAuth{
							Metadata: tunnelTypes.NewTestMetadata(),
							ClientCertificate: gke.ClientCertificate{
								Metadata:         tunnelTypes.NewTestMetadata(),
								IssueCertificate: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
							Username: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0053": {
		{
			name: "Master authorized network with public CIDR",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: tunnelTypes.NewTestMetadata(),
							CIDRs: []tunnelTypes.StringValue{
								tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Master authorized network with private CIDR",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MasterAuthorizedNetworks: gke.MasterAuthorizedNetworks{
							Metadata: tunnelTypes.NewTestMetadata(),
							CIDRs: []tunnelTypes.StringValue{
								tunnelTypes.String("10.10.128.0/24", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0057": {
		{
			name: "Cluster node pools metadata exposed by default",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: tunnelTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     tunnelTypes.NewTestMetadata(),
								NodeMetadata: tunnelTypes.String("UNSPECIFIED", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Node pool metadata exposed",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: tunnelTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     tunnelTypes.NewTestMetadata(),
								NodeMetadata: tunnelTypes.String("SECURE", tunnelTypes.NewTestMetadata()),
							},
						},
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata: tunnelTypes.NewTestMetadata(),
									WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
										Metadata:     tunnelTypes.NewTestMetadata(),
										NodeMetadata: tunnelTypes.String("EXPOSE", tunnelTypes.NewTestMetadata()),
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
			name: "Cluster node pools metadata secured",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata: tunnelTypes.NewTestMetadata(),
							WorkloadMetadataConfig: gke.WorkloadMetadataConfig{
								Metadata:     tunnelTypes.NewTestMetadata(),
								NodeMetadata: tunnelTypes.String("SECURE", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0054": {
		{
			name: "Cluster node config image type set to Ubuntu",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  tunnelTypes.NewTestMetadata(),
							ImageType: tunnelTypes.String("UBUNTU", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster node pool image type set to Ubuntu",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  tunnelTypes.NewTestMetadata(),
							ImageType: tunnelTypes.String("COS", tunnelTypes.NewTestMetadata()),
						},
						NodePools: []gke.NodePool{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								NodeConfig: gke.NodeConfig{
									Metadata:  tunnelTypes.NewTestMetadata(),
									ImageType: tunnelTypes.String("UBUNTU", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster node config image type set to Container-Optimized OS",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NodeConfig: gke.NodeConfig{
							Metadata:  tunnelTypes.NewTestMetadata(),
							ImageType: tunnelTypes.String("COS_CONTAINERD", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0055": {
		{
			name: "Cluster shielded nodes disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						EnableShieldedNodes: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster shielded nodes enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						EnableShieldedNodes: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0051": {
		{
			name: "Cluster with no resource labels defined",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						ResourceLabels: tunnelTypes.Map(map[string]string{}, tunnelTypes.NewTestMetadata().GetMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with resource labels defined",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ResourceLabels: tunnelTypes.Map(map[string]string{
							"env": "staging",
						}, tunnelTypes.NewTestMetadata().GetMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0062": {
		{
			name: "Cluster legacy ABAC enabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableLegacyABAC: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster legacy ABAC disabled",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableLegacyABAC: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0050": {
		{
			name: "Cluster node config with default service account",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:              tunnelTypes.NewTestMetadata(),
						RemoveDefaultNodePool: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       tunnelTypes.NewTestMetadata(),
							ServiceAccount: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster node config with service account provided",
			input: state.State{Google: google.Google{GKE: gke.GKE{
				Clusters: []gke.Cluster{
					{
						Metadata:              tunnelTypes.NewTestMetadata(),
						RemoveDefaultNodePool: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						NodeConfig: gke.NodeConfig{
							Metadata:       tunnelTypes.NewTestMetadata(),
							ServiceAccount: tunnelTypes.String("service-account", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
