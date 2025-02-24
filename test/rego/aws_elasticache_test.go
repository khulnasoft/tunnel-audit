package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/elasticache"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsElastiCacheTestCases)
}

var awsElastiCacheTestCases = testCases{
	"AVD-AWS-0049": {
		{
			name: "ElastiCache security group with no description provided",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ElastiCache security group with description",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				SecurityGroups: []elasticache.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("some decent description", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0045": {
		{
			name: "ElastiCache replication group with at-rest encryption disabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						AtRestEncryptionEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ElastiCache replication group with at-rest encryption enabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                tunnelTypes.NewTestMetadata(),
						AtRestEncryptionEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0050": {
		{
			name: "Cluster snapshot retention days set to 0",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               tunnelTypes.NewTestMetadata(),
						Engine:                 tunnelTypes.String("redis", tunnelTypes.NewTestMetadata()),
						NodeType:               tunnelTypes.String("cache.m4.large", tunnelTypes.NewTestMetadata()),
						SnapshotRetentionLimit: tunnelTypes.Int(0, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster snapshot retention days set to 5",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				Clusters: []elasticache.Cluster{
					{
						Metadata:               tunnelTypes.NewTestMetadata(),
						Engine:                 tunnelTypes.String("redis", tunnelTypes.NewTestMetadata()),
						NodeType:               tunnelTypes.String("cache.m4.large", tunnelTypes.NewTestMetadata()),
						SnapshotRetentionLimit: tunnelTypes.Int(5, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0051": {
		{
			name: "ElastiCache replication group with in-transit encryption disabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                 tunnelTypes.NewTestMetadata(),
						TransitEncryptionEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ElastiCache replication group with in-transit encryption enabled",
			input: state.State{AWS: aws.AWS{ElastiCache: elasticache.ElastiCache{
				ReplicationGroups: []elasticache.ReplicationGroup{
					{
						Metadata:                 tunnelTypes.NewTestMetadata(),
						TransitEncryptionEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
