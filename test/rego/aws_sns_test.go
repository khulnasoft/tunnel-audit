package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/sns"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsSnsTestCases)
}

var awsSnsTestCases = testCases{
	"AVD-AWS-0095": {
		{
			name: "AWS SNS Topic without encryption",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("alias/aws/sns", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("some-ok-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0136": {
		{
			name: "AWS SNS Topic without encryption",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("alias/aws/sns", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: state.State{AWS: aws.AWS{SNS: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("some-ok-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
