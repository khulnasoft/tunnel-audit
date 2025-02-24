package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/ssm"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsSsmTestCases)
}

var awsSsmTestCases = testCases{
	"AVD-AWS-0098": {
		{
			name: "AWS SSM missing KMS key",
			input: state.State{AWS: aws.AWS{SSM: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SSM with default KMS key",
			input: state.State{AWS: aws.AWS{SSM: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String(ssm.DefaultKMSKeyID, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SSM with proper KMS key",
			input: state.State{AWS: aws.AWS{SSM: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("some-ok-key", tunnelTypes.NewTestMetadata()),
					},
				}}},
			},
			expected: false,
		},
	},
}
