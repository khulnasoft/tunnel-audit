package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/config"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsConfigTestCases)
}

var awsConfigTestCases = testCases{
	"AVD-AWS-0019": {
		{
			name: "AWS Config aggregator source with all regions set to false",
			input: state.State{AWS: aws.AWS{Config: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         tunnelTypes.NewTestMetadata(),
					SourceAllRegions: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			},
			}},
			expected: true,
		},
		{
			name: "AWS Config aggregator source with all regions set to true",
			input: state.State{AWS: aws.AWS{Config: config.Config{
				ConfigurationAggregrator: config.ConfigurationAggregrator{
					Metadata:         tunnelTypes.NewTestMetadata(),
					SourceAllRegions: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
}
