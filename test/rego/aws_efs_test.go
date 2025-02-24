package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/efs"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsEfsTestCases)
}

var awsEfsTestCases = testCases{
	"AVD-AWS-0037": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{EFS: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						Encrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					}},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{EFS: efs.EFS{
				FileSystems: []efs.FileSystem{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						Encrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					}},
			}}},
			expected: false,
		},
	},
}
