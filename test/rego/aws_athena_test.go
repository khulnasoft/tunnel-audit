package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/athena"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsAthenaTestCases)
}

var awsAthenaTestCases = testCases{
	"AVD-AWS-0006": {
		{
			name: "AWS Athena database unencrypted",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Databases: []athena.Database{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(athena.EncryptionTypeNone, tunnelTypes.NewTestMetadata()),
						},
					},
				}}},
			},
			expected: true,
		},
		{
			name: "AWS Athena workgroup unencrypted",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(athena.EncryptionTypeNone, tunnelTypes.NewTestMetadata()),
						},
					},
				}}},
			},
			expected: true,
		},
		{
			name: "AWS Athena database and workgroup encrypted",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Databases: []athena.Database{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(athena.EncryptionTypeSSEKMS, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				Workgroups: []athena.Workgroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: athena.EncryptionConfiguration{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(athena.EncryptionTypeSSEKMS, tunnelTypes.NewTestMetadata()),
						},
					},
				}}},
			},
			expected: false,
		},
	},
	"AVD-AWS-0007": {
		{
			name: "AWS Athena workgroup doesn't enforce configuration",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata:             tunnelTypes.NewTestMetadata(),
						EnforceConfiguration: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Athena workgroup enforces configuration",
			input: state.State{AWS: aws.AWS{Athena: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata:             tunnelTypes.NewTestMetadata(),
						EnforceConfiguration: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
