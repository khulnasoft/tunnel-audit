package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/kinesis"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsKinesisTestCases)
}

var awsKinesisTestCases = testCases{
	"AVD-AWS-0064": {
		{
			name: "AWS Kinesis Stream with no encryption",
			input: state.State{AWS: aws.AWS{Kinesis: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String("NONE", tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption but no key",
			input: state.State{AWS: aws.AWS{Kinesis: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(kinesis.EncryptionTypeKMS, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption and key",
			input: state.State{AWS: aws.AWS{Kinesis: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(kinesis.EncryptionTypeKMS, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
