package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/cloudtrail"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/cloudwatch"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsCloudWatchTestCases)
}

var awsCloudWatchTestCases = testCases{
	"AVD-AWS-0017": {
		{
			name: "AWS CloudWatch with unencrypted log group",
			input: state.State{AWS: aws.AWS{CloudWatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS CloudWatch with encrypted log group",
			input: state.State{AWS: aws.AWS{CloudWatch: cloudwatch.CloudWatch{
				LogGroups: []cloudwatch.LogGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0151": {
		{
			name: "Multi-region CloudTrail alarms on CloudTrail configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									FilterName:    tunnelTypes.String("CloudTrailConfigurationChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`   {($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("CloudTrailConfigurationChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("CloudTrailConfigurationChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("CloudTrailConfigurationChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for CloudTrail configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("CloudTrailConfigurationChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0153": {
		{
			name: "Multi-region CloudTrail alarms on CMK disabled or scheduled deletion",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									FilterName:    tunnelTypes.String("CMKDisbledOrScheduledDelete", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("CMKDisbledOrScheduledDelete", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("CMKDisbledOrScheduledDelete", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("CMKDisbledOrScheduledDelete", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for CMK Disabled or scheduled deletion",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("CMKDisbledOrScheduledDelete", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0155": {
		{
			name: "Multi-region CloudTrail alarms on Config configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									FilterName:    tunnelTypes.String("ConfigConfigurationChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("ConfigConfigurationChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("ConfigConfigurationChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("ConfigConfigurationChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Config configuration change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("ConfigConfigurationChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0152": {
		{
			name: "Multi-region CloudTrail alarms on Console login failure",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									FilterName:    tunnelTypes.String("ConsoleLoginFailure", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("ConsoleLoginFailure", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("ConsoleLoginFailure", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("ConsoleLoginFailure", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for console login failure",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("ConsoleLoginFailure", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0150": {
		{
			name: "Multi-region CloudTrail alarms on IAM Policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("IAMPolicyChanged", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventName=DeleteGroupPolicy) || 
	($.eventName=DeleteRolePolicy) || 
	($.eventName=DeleteUserPolicy) || 
	($.eventName=PutGroupPolicy) || 
	($.eventName=PutRolePolicy) || 
	($.eventName=PutUserPolicy) || 
	($.eventName=CreatePolicy) || 
	($.eventName=DeletePolicy) || 
	($.eventName=CreatePolicyVersion) || 
	($.eventName=DeletePolicyVersion) || 
	($.eventName=AttachRolePolicy) ||
	($.eventName=DetachRolePolicy) ||
	($.eventName=AttachUserPolicy) || 
	($.eventName=DetachUserPolicy) || 
	($.eventName=AttachGroupPolicy) || 
	($.eventName=DetachGroupPolicy)}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("IAMPolicyChanged", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("IAMPolicyChanged", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("IAMPolicyChanged", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for IAM Policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("CloudTrail_Unauthorized_API_Call", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0157": {
		{
			name: "Multi-region CloudTrail alarms on network acl changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("NACLChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventName=CreateNetworkAcl) || 
						($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || 
						($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || 
						($.eventName=ReplaceNetworkAclAssociation)}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("NACLChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("NACLChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("NACLChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for network acl changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("NACLChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0158": {
		{
			name: "Multi-region CloudTrail alarms on network gateway changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("NetworkGatewayChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventName=CreateCustomerGateway) || 
						($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || 
						($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || 
						($.eventName=DetachInternetGateway)}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("NetworkGatewayChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("NetworkGatewayChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("NetworkGatewayChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for network gateway changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("NetworkGatewayChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0148": {
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("NonMFALogin", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`($.eventName = "ConsoleLogin") && 
	($.additionalEventData.MFAUsed != "Yes") && 
	($.userIdentity.type=="IAMUser") && 
	($.responseElements.ConsoleLogin == "Success")`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("NonMFALogin", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("NonMFALogin", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("NonMFALogin", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Unauthorized API calls",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("CloudTrail_Unauthorized_API_Call", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0174": {
		{
			name: "alarm exists",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Arn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									FilterName:    tunnelTypes.String("OrganizationEvents", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String("{ $.eventSource = \"organizations.amazonaws.com\" }", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							MetricName: tunnelTypes.String("OrganizationEvents", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "metric filter does not exist",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Arn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}},
			expected: true,
		},
		{
			name: "alarm does not exist",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Arn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									FilterName:    tunnelTypes.String("OrganizationEvents", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String("{ $.eventSource = \"organizations.amazonaws.com\" }", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0149": {
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									FilterName:    tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`$.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS && &.eventType != "AwsServiceEvent"`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail alarms on Non-MFA login",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("RootUserUsage", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0154": {
		{
			name: "Multi-region CloudTrail alarms on S3 bucket policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("BucketPolicyChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || 
						($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || 
						($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) ||
						 ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("BucketPolicyChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("BucketPolicyChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("BucketPolicyChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for S3 bucket policy change",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("BucketPolicyChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0156": {
		{
			name: "Multi-region CloudTrail alarms on security group changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("SecurityGroupChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventName=AuthorizeSecurityGroupIngress) || 
						($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) ||
						($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || 
						($.eventName=DeleteSecurityGroup)}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("SecurityGroupChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("SecurityGroupChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("SecurityGroupChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for security group changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("SecurityGroupChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0147": {
		{
			name: "Multi-region CloudTrail alarms on Unauthorized API calls",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:      tunnelTypes.NewTestMetadata(),
									FilterName:    tunnelTypes.String("UnauthorizedAPIUsage", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("CloudTrail_Unauthorized_API_Call", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("UnauthorizedAPIUsage", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("UnauthorizedAPIUsage", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for Unauthorized API calls",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("CloudTrail_Unauthorized_API_Call", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
	"AVD-AWS-0160": {
		{
			name: "Multi-region CloudTrail alarms on VPC changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata: tunnelTypes.NewTestMetadata(),
							Arn:      tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{
								{
									Metadata:   tunnelTypes.NewTestMetadata(),
									FilterName: tunnelTypes.String("VPCChange", tunnelTypes.NewTestMetadata()),
									FilterPattern: tunnelTypes.String(`{($.eventName=CreateVpc) || 
						($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || 
						($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || 
						($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || 
						($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || 
						($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}`, tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:   tunnelTypes.NewTestMetadata(),
							AlarmName:  tunnelTypes.String("VPCChange", tunnelTypes.NewTestMetadata()),
							MetricName: tunnelTypes.String("VPCChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{
									Metadata: tunnelTypes.NewTestMetadata(),
									ID:       tunnelTypes.String("VPCChange", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}},
			expected: false,
		},
		{
			name: "Multi-region CloudTrail has no filter for VPC changes",
			input: state.State{AWS: aws.AWS{
				CloudTrail: cloudtrail.CloudTrail{
					Trails: []cloudtrail.Trail{
						{
							Metadata:                  tunnelTypes.NewTestMetadata(),
							CloudWatchLogsLogGroupArn: tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							IsLogging:                 tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							IsMultiRegion:             tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
				CloudWatch: cloudwatch.CloudWatch{
					LogGroups: []cloudwatch.LogGroup{
						{
							Metadata:      tunnelTypes.NewTestMetadata(),
							Arn:           tunnelTypes.String("arn:aws:cloudwatch:us-east-1:123456789012:log-group:cloudtrail-logging", tunnelTypes.NewTestMetadata()),
							MetricFilters: []cloudwatch.MetricFilter{},
						},
					},
					Alarms: []cloudwatch.Alarm{
						{
							Metadata:  tunnelTypes.NewTestMetadata(),
							AlarmName: tunnelTypes.String("VPCChange", tunnelTypes.NewTestMetadata()),
							Metrics: []cloudwatch.MetricDataQuery{
								{},
							},
						},
					},
				},
			}},
			expected: true,
		},
	},
}
