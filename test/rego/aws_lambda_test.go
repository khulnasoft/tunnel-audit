package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/lambda"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsLambdaTestCases)
}

var awsLambdaTestCases = testCases{
	"AVD-AWS-0066": {
		{
			name: "Lambda function with no tracing mode specified",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: tunnelTypes.NewTestMetadata(),
							Mode:     tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Lambda function with active tracing mode",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: tunnelTypes.NewTestMetadata(),
							Mode:     tunnelTypes.String(lambda.TracingModeActive, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0067": {
		{
			name: "Lambda function permission missing source ARN",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								Principal: tunnelTypes.String("sns.amazonaws.com", tunnelTypes.NewTestMetadata()),
								SourceARN: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Lambda function permission with source ARN",
			input: state.State{AWS: aws.AWS{Lambda: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								Principal: tunnelTypes.String("sns.amazonaws.com", tunnelTypes.NewTestMetadata()),
								SourceARN: tunnelTypes.String("source-arn", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
