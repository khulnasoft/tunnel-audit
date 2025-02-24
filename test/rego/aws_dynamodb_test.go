package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/dynamodb"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsDynamodbTestCases)
}

var awsDynamodbTestCases = testCases{
	"AVD-AWS-0023": {
		{
			name: "Cluster with SSE disabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with SSE enabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0024": {
		{
			name: "Cluster with point in time recovery disabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						PointInTimeRecovery: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with point in time recovery enabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				DAXClusters: []dynamodb.DAXCluster{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						PointInTimeRecovery: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0025": {
		{
			name: "Cluster encryption missing KMS key",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster encryption using default KMS key",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String(dynamodb.DefaultKMSKeyID, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster encryption using proper KMS key",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("some-ok-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "KMS key exist, but SSE is not enabled",
			input: state.State{AWS: aws.AWS{DynamoDB: dynamodb.DynamoDB{
				Tables: []dynamodb.Table{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ServerSideEncryption: dynamodb.ServerSideEncryption{
							Enabled:  tunnelTypes.BoolDefault(false, tunnelTypes.NewTestMetadata()),
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("some-ok-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
