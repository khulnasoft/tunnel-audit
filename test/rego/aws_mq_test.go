package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/mq"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsMqTestCases)
}

var awsMqTestCases = testCases{
	"AVD-AWS-0070": {
		{
			name: "AWS MQ Broker without audit logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Audit:    tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS MQ Broker with audit logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							Audit:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0071": {
		{
			name: "AWS MQ Broker without general logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							General:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS MQ Broker with general logging",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Logging: mq.Logging{
							Metadata: tunnelTypes.NewTestMetadata(),
							General:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0072": {
		{
			name: "AWS MQ Broker with public access enabled",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						PublicAccess: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS MQ Broker with public access disabled",
			input: state.State{AWS: aws.AWS{MQ: mq.MQ{
				Brokers: []mq.Broker{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						PublicAccess: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
