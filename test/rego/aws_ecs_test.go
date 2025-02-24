package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/ecs"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsEcsTestCases)
}

var awsEcsTestCases = testCases{
	"AVD-AWS-0034": {
		{
			name: "Cluster with disabled container insights",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 tunnelTypes.NewTestMetadata(),
							ContainerInsightsEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Cluster with enabled container insights",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				Clusters: []ecs.Cluster{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Settings: ecs.ClusterSettings{
							Metadata:                 tunnelTypes.NewTestMetadata(),
							ContainerInsightsEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0035": {
		{
			name: "ECS task definition unencrypted volume",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Volumes: []ecs.Volume{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									Metadata:                 tunnelTypes.NewTestMetadata(),
									TransitEncryptionEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "ECS task definition encrypted volume",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Volumes: []ecs.Volume{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
									Metadata:                 tunnelTypes.NewTestMetadata(),
									TransitEncryptionEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0036": {
		// {
		// 	name: "Task definition with plaintext sensitive information",
		// 	input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
		// 		TaskDefinitions: []ecs.TaskDefinition{
		// 			{
		// 				Metadata: tunnelTypes.NewTestMetadata(),
		// 				ContainerDefinitions: []ecs.ContainerDefinition{
		// 					{
		// 						Metadata:  tunnelTypes.NewTestMetadata(),
		// 						Name:      tunnelTypes.String("my_service", tunnelTypes.NewTestMetadata()),
		// 						Image:     tunnelTypes.String("my_image", tunnelTypes.NewTestMetadata()),
		// 						CPU:       tunnelTypes.Int(2, tunnelTypes.NewTestMetadata()),
		// 						Memory:    tunnelTypes.Int(256, tunnelTypes.NewTestMetadata()),
		// 						Essential: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
		// 						Environment: []ecs.EnvVar{
		// 							{
		// 								Name:  "ENVIRONMENT",
		// 								Value: "development",
		// 							},
		// 							{
		// 								Name:  "DATABASE_PASSWORD",
		// 								Value: "password123",
		// 							},
		// 						},
		// 					},
		// 				},
		// 			},
		// 		},
		// 	}}},
		// 	expected: true,
		// },
		{
			name: "Task definition without sensitive information",
			input: state.State{AWS: aws.AWS{ECS: ecs.ECS{
				TaskDefinitions: []ecs.TaskDefinition{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ContainerDefinitions: []ecs.ContainerDefinition{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								Name:      tunnelTypes.String("my_service", tunnelTypes.NewTestMetadata()),
								Image:     tunnelTypes.String("my_image", tunnelTypes.NewTestMetadata()),
								CPU:       tunnelTypes.String("2", tunnelTypes.NewTestMetadata()),
								Memory:    tunnelTypes.String("256", tunnelTypes.NewTestMetadata()),
								Essential: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								Environment: []ecs.EnvVar{
									{
										Name:  tunnelTypes.StringTest("ENVIRONMENT"),
										Value: tunnelTypes.StringTest("development"),
									},
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
