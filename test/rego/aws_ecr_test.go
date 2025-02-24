package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/ecr"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/iam"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
	"github.com/liamg/iamgo"
)

func init() {
	addTests(awsEcrTestCases)
}

var awsEcrTestCases = testCases{
	"AVD-AWS-0030": {
		{
			name: "ECR repository with image scans disabled",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   tunnelTypes.NewTestMetadata(),
							ScanOnPush: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository with image scans enabled",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ImageScanning: ecr.ImageScanning{
							Metadata:   tunnelTypes.NewTestMetadata(),
							ScanOnPush: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0031": {
		{
			name: "ECR mutable image tags",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata:           tunnelTypes.NewTestMetadata(),
						ImageTagsImmutable: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR immutable image tags",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata:           tunnelTypes.NewTestMetadata(),
						ImageTagsImmutable: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0032": {
		{
			name: "ECR repository policy with wildcard principal",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithAllPrincipals(true)
							sb.WithActions([]string{
								"ecr:GetDownloadUrlForLayer",
								"ecr:BatchGetImage",
								"ecr:BatchCheckLayerAvailability",
								"ecr:PutImage",
								"ecr:InitiateLayerUpload",
								"ecr:UploadLayerPart",
								"ecr:CompleteLayerUpload",
								"ecr:DescribeRepositories",
								"ecr:GetRepositoryPolicy",
								"ecr:ListImages",
								"ecr:DeleteRepository",
								"ecr:BatchDeleteImage",
								"ecr:SetRepositoryPolicy",
								"ecr:DeleteRepositoryPolicy",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2021-10-07")
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
			name: "ECR repository policy with specific principal",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithAWSPrincipals([]string{"arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"})
							sb.WithActions([]string{
								"ecr:GetDownloadUrlForLayer",
								"ecr:BatchGetImage",
								"ecr:BatchCheckLayerAvailability",
								"ecr:PutImage",
								"ecr:InitiateLayerUpload",
								"ecr:UploadLayerPart",
								"ecr:CompleteLayerUpload",
								"ecr:DescribeRepositories",
								"ecr:GetRepositoryPolicy",
								"ecr:ListImages",
								"ecr:DeleteRepository",
								"ecr:BatchDeleteImage",
								"ecr:SetRepositoryPolicy",
								"ecr:DeleteRepositoryPolicy",
							})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2021-10-07")
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
	"AVD-AWS-0033": {
		{
			name: "ECR repository not using KMS encryption",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(ecr.EncryptionTypeAES256, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository using KMS encryption but missing key",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(ecr.EncryptionTypeKMS, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECR repository encrypted with KMS key",
			input: state.State{AWS: aws.AWS{ECR: ecr.ECR{
				Repositories: []ecr.Repository{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ecr.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Type:     tunnelTypes.String(ecr.EncryptionTypeKMS, tunnelTypes.NewTestMetadata()),
							KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
