package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/redshift"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsRedshiftTestCases)
}

var awsRedshiftTestCases = testCases{
	"AVD-AWS-0083": {
		{
			name: "Redshift security group without description",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift security group with description",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("security group description", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0084": {
		{
			name: "Redshift Cluster with encryption disabled",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift Cluster missing KMS key",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift Cluster encrypted with KMS key",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: redshift.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0085": {
		{
			name: "security groups present",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				SecurityGroups: []redshift.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
					},
				},
			}}},
			expected: true,
		},
		{
			name:     "no security groups",
			input:    state.State{AWS: aws.AWS{Redshift: redshift.Redshift{}}},
			expected: false,
		},
	},
	"AVD-AWS-0127": {
		{
			name: "Redshift Cluster missing subnet name",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						SubnetGroupName: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Redshift Cluster with subnet name",
			input: state.State{AWS: aws.AWS{Redshift: redshift.Redshift{
				Clusters: []redshift.Cluster{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						SubnetGroupName: tunnelTypes.String("redshift-subnet", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
