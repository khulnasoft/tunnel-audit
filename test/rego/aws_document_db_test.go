package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/documentdb"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsDocumentDBTestCases)
}

var awsDocumentDBTestCases = testCases{
	"AVD-AWS-0020": {
		{
			name: "DocDB Cluster not exporting logs",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EnabledLogExports: []tunnelTypes.StringValue{
							tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB Cluster exporting audit logs",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EnabledLogExports: []tunnelTypes.StringValue{
							tunnelTypes.String(documentdb.LogExportAudit, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "DocDB Cluster exporting profiler logs",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EnabledLogExports: []tunnelTypes.StringValue{
							tunnelTypes.String(documentdb.LogExportProfiler, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0021": {
		{
			name: "DocDB unencrypted storage",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						StorageEncrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB encrypted storage",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						StorageEncrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0022": {
		{
			name: "DocDB Cluster encryption missing KMS key",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB Instance encryption missing KMS key",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("kms-key", tunnelTypes.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "DocDB Cluster and Instance encrypted with proper KMS keys",
			input: state.State{AWS: aws.AWS{DocumentDB: documentdb.DocumentDB{
				Clusters: []documentdb.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("kms-key", tunnelTypes.NewTestMetadata()),
						Instances: []documentdb.Instance{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								KMSKeyID: tunnelTypes.String("kms-key", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
