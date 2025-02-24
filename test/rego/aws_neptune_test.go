package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/neptune"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsNeptuneTestCases)
}

var awsNeptuneTestCases = testCases{
	"AVD-AWS-0075": {
		{
			name: "Neptune Cluster with audit logging disabled",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: neptune.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Audit:    tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Neptune Cluster with audit logging enabled",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: neptune.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Audit:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0076": {
		{
			name: "Neptune Cluster without storage encryption",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						StorageEncrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Neptune Cluster with storage encryption",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						StorageEncrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0128": {
		{
			name: "Neptune Cluster missing KMS key",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Neptune Cluster encrypted with KMS key",
			input: state.State{AWS: aws.AWS{Neptune: neptune.Neptune{
				Clusters: []neptune.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
