package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/workspaces"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsWorkspacesTestCases)
}

var awsWorkspacesTestCases = testCases{
	"AVD-AWS-0109": {
		{
			name: "AWS Workspace with unencrypted root volume",
			input: state.State{AWS: aws.AWS{WorkSpaces: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: tunnelTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: tunnelTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Workspace with unencrypted user volume",
			input: state.State{AWS: aws.AWS{WorkSpaces: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: tunnelTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: tunnelTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},

		{
			name: "AWS Workspace with encrypted user and root volumes",
			input: state.State{AWS: aws.AWS{WorkSpaces: workspaces.WorkSpaces{
				WorkSpaces: []workspaces.WorkSpace{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RootVolume: workspaces.Volume{
							Metadata: tunnelTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
						UserVolume: workspaces.Volume{
							Metadata: tunnelTypes.NewTestMetadata(),
							Encryption: workspaces.Encryption{
								Metadata: tunnelTypes.NewTestMetadata(),
								Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
