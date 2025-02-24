package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/msk"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsMskTestCases)
}

var awsMskTestCases = testCases{
	"AVD-AWS-0179": {
		{
			name: "Cluster with at rest encryption enabled",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EncryptionAtRest: msk.EncryptionAtRest{
							Metadata:  tunnelTypes.NewTestMetadata(),
							KMSKeyARN: tunnelTypes.String("foo-bar-key", tunnelTypes.NewTestMetadata()),
							Enabled:   tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Cluster with at rest encryption disabled",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0073": {
		{
			name: "Cluster client broker with plaintext encryption",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     tunnelTypes.NewTestMetadata(),
							ClientBroker: tunnelTypes.String(msk.ClientBrokerEncryptionPlaintext, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster client broker with plaintext or TLS encryption",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     tunnelTypes.NewTestMetadata(),
							ClientBroker: tunnelTypes.String(msk.ClientBrokerEncryptionTLSOrPlaintext, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster client broker with TLS encryption",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EncryptionInTransit: msk.EncryptionInTransit{
							Metadata:     tunnelTypes.NewTestMetadata(),
							ClientBroker: tunnelTypes.String(msk.ClientBrokerEncryptionTLS, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0074": {
		{
			name: "Cluster with logging disabled",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: tunnelTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: tunnelTypes.NewTestMetadata(),
									Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: tunnelTypes.NewTestMetadata(),
									Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: tunnelTypes.NewTestMetadata(),
									Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster logging to S3",
			input: state.State{AWS: aws.AWS{MSK: msk.MSK{
				Clusters: []msk.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: msk.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Broker: msk.BrokerLogging{
								Metadata: tunnelTypes.NewTestMetadata(),
								S3: msk.S3Logging{
									Metadata: tunnelTypes.NewTestMetadata(),
									Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								},
								Cloudwatch: msk.CloudwatchLogging{
									Metadata: tunnelTypes.NewTestMetadata(),
									Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
								Firehose: msk.FirehoseLogging{
									Metadata: tunnelTypes.NewTestMetadata(),
									Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
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
