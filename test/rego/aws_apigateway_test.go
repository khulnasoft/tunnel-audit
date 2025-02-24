package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/apigateway"
	v1 "github.com/khulnasoft/tunnel/pkg/iac/providers/aws/apigateway/v1"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsApigatewayTestCases)
}

var awsApigatewayTestCases = testCases{
	"AVD-AWS-0001": {
		{
			name: "API Gateway stage with no log group ARN",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              tunnelTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway stage with log group ARN",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              tunnelTypes.NewTestMetadata(),
									CloudwatchLogGroupARN: tunnelTypes.String("log-group-arn", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0002": {
		{
			name: "API Gateway stage with unencrypted cache",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           tunnelTypes.NewTestMetadata(),
										CacheDataEncrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
										CacheEnabled:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway stage with encrypted cache",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           tunnelTypes.NewTestMetadata(),
										CacheDataEncrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										CacheEnabled:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
		{
			name: "API Gateway stage with caching disabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:           tunnelTypes.NewTestMetadata(),
										CacheDataEncrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
										CacheEnabled:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0003": {
		{
			name: "API Gateway stage with X-Ray tracing disabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata:           tunnelTypes.NewTestMetadata(),
								XRayTracingEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway stage with X-Ray tracing enabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata:           tunnelTypes.NewTestMetadata(),
								XRayTracingEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0004": {
		{
			name: "API GET method without authorization",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          tunnelTypes.NewTestMetadata(),
										HTTPMethod:        tunnelTypes.String("GET", tunnelTypes.NewTestMetadata()),
										APIKeyRequired:    tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
										AuthorizationType: tunnelTypes.String(v1.AuthorizationNone, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API OPTION method without authorization",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          tunnelTypes.NewTestMetadata(),
										HTTPMethod:        tunnelTypes.String("OPTION", tunnelTypes.NewTestMetadata()),
										APIKeyRequired:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
										AuthorizationType: tunnelTypes.String(v1.AuthorizationNone, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
		{
			name: "API GET method with IAM authorization",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          tunnelTypes.NewTestMetadata(),
										HTTPMethod:        tunnelTypes.String("GET", tunnelTypes.NewTestMetadata()),
										APIKeyRequired:    tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
										AuthorizationType: tunnelTypes.String(v1.AuthorizationIAM, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0005": {
		{
			name: "API Gateway domain name with TLS version 1.0",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				DomainNames: []v1.DomainName{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						SecurityPolicy: tunnelTypes.String("TLS_1_0", tunnelTypes.NewTestMetadata()),
					},
				},
			}}}},
			expected: true,
		},
		{
			name: "API Gateway domain name with TLS version 1.2",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				DomainNames: []v1.DomainName{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						SecurityPolicy: tunnelTypes.String("TLS_1_2", tunnelTypes.NewTestMetadata()),
					},
				},
			}}}},
			expected: false,
		},
	},
	"AVD-AWS-0190": {
		{
			name: "API Gateway stage with caching disabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:     tunnelTypes.NewTestMetadata(),
										CacheEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: true,
		},

		{
			name: "API Gateway stage with caching enabled",
			input: state.State{AWS: aws.AWS{APIGateway: apigateway.APIGateway{V1: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								RESTMethodSettings: []v1.RESTMethodSettings{
									{
										Metadata:     tunnelTypes.NewTestMetadata(),
										CacheEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			}}}},
			expected: false,
		},
	},
}
