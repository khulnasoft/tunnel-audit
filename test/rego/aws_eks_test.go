package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/eks"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsEksTestCases)
}

var awsEksTestCases = testCases{
	"AVD-AWS-0038": {
		{
			name: "EKS cluster with all cluster logging disabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							Audit:             tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							Authenticator:     tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							ControllerManager: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							Scheduler:         tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS cluster with only some cluster logging enabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							Audit:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Authenticator:     tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							ControllerManager: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Scheduler:         tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS cluster with all cluster logging enabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: eks.Logging{
							API:               tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Audit:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Authenticator:     tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							ControllerManager: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Scheduler:         tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0039": {
		{
			name: "EKS Cluster with no secrets in the resources attribute",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Secrets:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute but no KMS key",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Secrets:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with secrets in the resources attribute and a KMS key",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: eks.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Secrets:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-arn", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0041": {
		{
			name: "EKS Cluster with public access CIDRs actively set to open",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						PublicAccessCIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with public access enabled but private CIDRs",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						PublicAccessCIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("10.2.0.0/8", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "EKS Cluster with public access disabled and private CIDRs",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						PublicAccessCIDRs: []tunnelTypes.StringValue{
							tunnelTypes.String("10.2.0.0/8", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0040": {
		{
			name: "EKS Cluster with public access enabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EKS Cluster with public access disabled",
			input: state.State{AWS: aws.AWS{EKS: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
