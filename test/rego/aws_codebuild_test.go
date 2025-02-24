package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/codebuild"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsCodeBuildTestCases)
}

var awsCodeBuildTestCases = testCases{
	"AVD-AWS-0018": {
		{
			name: "AWS Codebuild project with unencrypted artifact",
			input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          tunnelTypes.NewTestMetadata(),
							EncryptionEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Codebuild project with unencrypted secondary artifact",
			input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          tunnelTypes.NewTestMetadata(),
							EncryptionEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
						SecondaryArtifactSettings: []codebuild.ArtifactSettings{
							{
								Metadata:          tunnelTypes.NewTestMetadata(),
								EncryptionEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS Codebuild with encrypted artifacts",
			input: state.State{AWS: aws.AWS{CodeBuild: codebuild.CodeBuild{
				Projects: []codebuild.Project{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ArtifactSettings: codebuild.ArtifactSettings{
							Metadata:          tunnelTypes.NewTestMetadata(),
							EncryptionEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
						SecondaryArtifactSettings: []codebuild.ArtifactSettings{
							{
								Metadata:          tunnelTypes.NewTestMetadata(),
								EncryptionEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
