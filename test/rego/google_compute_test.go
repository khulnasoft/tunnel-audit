package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/google/compute"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(googleComputeTestCases)
}

var googleComputeTestCases = testCases{
	"AVD-GCP-0034": {
		{
			name: "Disk missing KMS key link",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   tunnelTypes.NewTestMetadata(),
							KMSKeyLink: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Disk with KMS key link provided",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   tunnelTypes.NewTestMetadata(),
							KMSKeyLink: tunnelTypes.String("kms-key-link", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0037": {
		{
			name: "Disk with plaintext encryption key",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							RawKey:   tunnelTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance disk with plaintext encryption key",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: tunnelTypes.NewTestMetadata(),
									RawKey:   tunnelTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Disks with no plaintext encryption keys",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							RawKey:   tunnelTypes.Bytes([]byte(""), tunnelTypes.NewTestMetadata()),
						},
					},
				},
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: tunnelTypes.NewTestMetadata(),
									RawKey:   tunnelTypes.Bytes([]byte(""), tunnelTypes.NewTestMetadata()),
								},
							},
						},
						AttachedDisks: []compute.Disk{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: tunnelTypes.NewTestMetadata(),
									RawKey:   tunnelTypes.Bytes([]byte(""), tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0045": {
		{
			name: "Instance shielded VM integrity monitoring disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:                   tunnelTypes.NewTestMetadata(),
							IntegrityMonitoringEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance shielded VM integrity monitoring enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:                   tunnelTypes.NewTestMetadata(),
							IntegrityMonitoringEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0067": {
		{
			name: "Instance shielded VM secure boot disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:          tunnelTypes.NewTestMetadata(),
							SecureBootEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance shielded VM secure boot enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:          tunnelTypes.NewTestMetadata(),
							SecureBootEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0041": {
		{
			name: "Instance shielded VM VTPM disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:    tunnelTypes.NewTestMetadata(),
							VTPMEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance shielded VM VTPM enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ShieldedVM: compute.ShieldedVMConfig{
							Metadata:    tunnelTypes.NewTestMetadata(),
							VTPMEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0029": {
		{
			name: "Subnetwork VPC flow logs disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								EnableFlowLogs: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Subnetwork VPC flow logs enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								EnableFlowLogs: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Proxy-only subnets and logs disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Subnetworks: []compute.SubNetwork{
							{
								Metadata:       tunnelTypes.NewTestMetadata(),
								EnableFlowLogs: tunnelTypes.BoolDefault(false, tunnelTypes.NewTestMetadata()),
								Purpose:        tunnelTypes.String("REGIONAL_MANAGED_PROXY", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0044": {
		{
			name: "Instance service account not specified",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Email:     tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							IsDefault: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance service account using the default email",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Email:     tunnelTypes.String("1234567890-compute@developer.gserviceaccount.com", tunnelTypes.NewTestMetadata()),
							IsDefault: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance service account with email provided",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServiceAccount: compute.ServiceAccount{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Email:     tunnelTypes.String("proper@email.com", tunnelTypes.NewTestMetadata()),
							IsDefault: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0043": {
		{
			name: "Instance IP forwarding enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						CanIPForward: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance IP forwarding disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						CanIPForward: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0036": {
		{
			name: "Instance OS login disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						OSLoginEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance OS login enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						OSLoginEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0030": {
		{
			name: "Instance project level SSH keys blocked",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:                    tunnelTypes.NewTestMetadata(),
						EnableProjectSSHKeyBlocking: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance project level SSH keys allowed",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:                    tunnelTypes.NewTestMetadata(),
						EnableProjectSSHKeyBlocking: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0035": {
		{
			name: "Firewall egress rule with multiple public destination addresses",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: tunnelTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: tunnelTypes.NewTestMetadata(),
										IsAllow:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										Enforced: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
									DestinationRanges: []tunnelTypes.StringValue{
										tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
										tunnelTypes.String("1.2.3.4/32", tunnelTypes.NewTestMetadata()),
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
			name: "Firewall egress rule with public destination address",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: tunnelTypes.NewTestMetadata(),
							EgressRules: []compute.EgressRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: tunnelTypes.NewTestMetadata(),
										IsAllow:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										Enforced: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
									DestinationRanges: []tunnelTypes.StringValue{
										tunnelTypes.String("1.2.3.4/32", tunnelTypes.NewTestMetadata()),
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
	"AVD-GCP-0027": {
		{
			name: "Firewall ingress rule with multiple public source addresses",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: tunnelTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: tunnelTypes.NewTestMetadata(),
										IsAllow:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										Enforced: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
									SourceRanges: []tunnelTypes.StringValue{
										tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
										tunnelTypes.String("1.2.3.4/32", tunnelTypes.NewTestMetadata()),
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
			name: "Firewall ingress rule with public source address",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Networks: []compute.Network{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Firewall: &compute.Firewall{
							Metadata: tunnelTypes.NewTestMetadata(),
							IngressRules: []compute.IngressRule{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									FirewallRule: compute.FirewallRule{
										Metadata: tunnelTypes.NewTestMetadata(),
										IsAllow:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										Enforced: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
									SourceRanges: []tunnelTypes.StringValue{
										tunnelTypes.String("1.2.3.4/32", tunnelTypes.NewTestMetadata()),
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
	"AVD-GCP-0031": {
		{
			name: "Network interface with public IP",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []compute.NetworkInterface{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								HasPublicIP: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Network interface without public IP",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						NetworkInterfaces: []compute.NetworkInterface{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								HasPublicIP: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0032": {
		{
			name: "Instance serial port enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableSerialPort: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance serial port disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableSerialPort: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0042": {
		{
			name: "Compute OS login disabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      tunnelTypes.NewTestMetadata(),
					EnableOSLogin: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Compute OS login enabled",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				ProjectMetadata: compute.ProjectMetadata{
					Metadata:      tunnelTypes.NewTestMetadata(),
					EnableOSLogin: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0039": {
		{
			name: "SSL policy minimum TLS version 1.0",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				SSLPolicies: []compute.SSLPolicy{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						MinimumTLSVersion: tunnelTypes.String("TLS_1_0", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SSL policy minimum TLS version 1.2",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				SSLPolicies: []compute.SSLPolicy{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						MinimumTLSVersion: tunnelTypes.String("TLS_1_2", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-GCP-0033": {
		{
			name: "Instance disk missing encryption key link",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   tunnelTypes.NewTestMetadata(),
									KMSKeyLink: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Instance disk encryption key link provided",
			input: state.State{Google: google.Google{Compute: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AttachedDisks: []compute.Disk{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   tunnelTypes.NewTestMetadata(),
									KMSKeyLink: tunnelTypes.String("kms-key-link", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
