package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/sam"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsSamTestCases)
}

var awsSamTestCases = testCases{
	"AVD-AWS-0112": {
		{
			name: "SAM API TLS v1.0",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       tunnelTypes.NewTestMetadata(),
							SecurityPolicy: tunnelTypes.String("TLS_1_0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SAM API TLS v1.2",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						DomainConfiguration: sam.DomainConfiguration{
							Metadata:       tunnelTypes.NewTestMetadata(),
							SecurityPolicy: tunnelTypes.String("TLS_1_2", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0113": {
		{
			name: "API logging not configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              tunnelTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API logging configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              tunnelTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: tunnelTypes.String("log-group-arn", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0110": {
		{
			name: "API unencrypted cache data",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           tunnelTypes.NewTestMetadata(),
							CacheDataEncrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API encrypted cache data",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RESTMethodSettings: sam.RESTMethodSettings{
							Metadata:           tunnelTypes.NewTestMetadata(),
							CacheDataEncrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0111": {
		{
			name: "API X-Ray tracing disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						TracingEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "API X-Ray tracing enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				APIs: []sam.API{
					{
						Metadata:       tunnelTypes.NewTestMetadata(),
						TracingEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0125": {
		{
			name: "SAM pass-through tracing mode",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				Functions: []sam.Function{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tracing:  tunnelTypes.String(sam.TracingModePassThrough, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SAM active tracing mode",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				Functions: []sam.Function{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tracing:  tunnelTypes.String(sam.TracingModeActive, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0116": {
		{
			name: "HTTP API logging not configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				HttpAPIs: []sam.HttpAPI{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              tunnelTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "HTTP API logging configured",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				HttpAPIs: []sam.HttpAPI{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						AccessLogging: sam.AccessLogging{
							Metadata:              tunnelTypes.NewTestMetadata(),
							CloudwatchLogGroupARN: tunnelTypes.String("log-group-arn", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0119": {
		{
			name: "State machine logging disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       tunnelTypes.NewTestMetadata(),
							LoggingEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "State machine logging enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						LoggingConfiguration: sam.LoggingConfiguration{
							Metadata:       tunnelTypes.NewTestMetadata(),
							LoggingEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0117": {
		{
			name: "State machine tracing disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "State machine tracing enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				StateMachines: []sam.StateMachine{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tracing: sam.TracingConfiguration{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0121": {
		{
			name: "SAM simple table SSE disabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				SimpleTables: []sam.SimpleTable{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SSESpecification: sam.SSESpecification{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "SAM simple table SSE enabled",
			input: state.State{AWS: aws.AWS{SAM: sam.SAM{
				SimpleTables: []sam.SimpleTable{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SSESpecification: sam.SSESpecification{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
