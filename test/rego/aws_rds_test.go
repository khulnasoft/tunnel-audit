package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/rds"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsRdsTestCases)
}

var awsRdsTestCases = testCases{
	"AVD-AWS-0133": {
		{
			name: "RDS Instance with performance insights disabled",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},

		{
			name: "RDS Instance with performance insights enabled and KMS key provided",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0079": {
		{
			name: "RDS Cluster with storage encryption disabled",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       tunnelTypes.NewTestMetadata(),
							EncryptStorage: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID:       tunnelTypes.String("kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled but missing KMS key",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       tunnelTypes.NewTestMetadata(),
							EncryptStorage: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID:       tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Cluster with storage encryption enabled and KMS key provided",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: rds.Encryption{
							Metadata:       tunnelTypes.NewTestMetadata(),
							EncryptStorage: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID:       tunnelTypes.String("kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0080": {
		{
			name: "RDS Instance with unencrypted storage",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             tunnelTypes.NewTestMetadata(),
						ReplicationSourceARN: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       tunnelTypes.NewTestMetadata(),
							EncryptStorage: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Instance with encrypted storage",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:             tunnelTypes.NewTestMetadata(),
						ReplicationSourceARN: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						Encryption: rds.Encryption{
							Metadata:       tunnelTypes.NewTestMetadata(),
							EncryptStorage: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0078": {
		{
			name: "RDS Instance with performance insights disabled",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "RDS Cluster instance with performance insights enabled but missing KMS key",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Instances: []rds.ClusterInstance{
							{
								Instance: rds.Instance{
									Metadata: tunnelTypes.NewTestMetadata(),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: tunnelTypes.NewTestMetadata(),
										Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
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
			name: "RDS Instance with performance insights enabled and KMS key provided",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0077": {
		{
			name: "RDS Cluster with 1 retention day (default)",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						ReplicationSourceARN:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: tunnelTypes.Int(1, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Instance with 1 retention day (default)",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						ReplicationSourceARN:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: tunnelTypes.Int(1, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "RDS Cluster with 5 retention days",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Clusters: []rds.Cluster{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						ReplicationSourceARN:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: tunnelTypes.Int(5, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "RDS Instance with 5 retention days",
			input: state.State{AWS: aws.AWS{RDS: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  tunnelTypes.NewTestMetadata(),
						ReplicationSourceARN:      tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						BackupRetentionPeriodDays: tunnelTypes.Int(5, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
