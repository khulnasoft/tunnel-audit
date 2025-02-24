package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/iam"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/sqs"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
	"github.com/liamg/iamgo"
)

func init() {
	addTests(awsSqsTestCases)
}

var awsSqsTestCases = testCases{
	"AVD-AWS-0096": {
		{
			name: "SQS Queue unencrypted",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          tunnelTypes.NewTestMetadata(),
							ManagedEncryption: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID:          tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          tunnelTypes.NewTestMetadata(),
							ManagedEncryption: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID:          tunnelTypes.String("alias/aws/sqs", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          tunnelTypes.NewTestMetadata(),
							ManagedEncryption: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							KMSKeyID:          tunnelTypes.String("some-ok-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          tunnelTypes.NewTestMetadata(),
							ManagedEncryption: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							KMSKeyID:          tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0097": {
		{
			name: "AWS SQS policy document with wildcard action statement",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"sqs:*",
							})
							sb.WithResources([]string{"arn:aws:sqs:::my-queue"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: tunnelTypes.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS SQS policy document with action statement list",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"sqs:SendMessage",
								"sqs:ReceiveMessage",
							})
							sb.WithResources([]string{"arn:aws:sqs:::my-queue"})
							sb.WithAWSPrincipals([]string{"*"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: tunnelTypes.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0135": {
		{
			name: "SQS Queue unencrypted",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("alias/aws/sqs", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: state.State{AWS: aws.AWS{SQS: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
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
