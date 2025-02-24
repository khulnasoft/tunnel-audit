package test

import (
	"time"

	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/iam"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
	"github.com/liamg/iamgo"
)

func init() {
	addTests(awsIamTestCases)
}

var awsIamTestCases = testCases{
	"AVD-AWS-0166": {
		{
			name: "User logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User logged in 50 days ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now().Add(-time.Hour*24*50), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "User last used access key 50 days ago but it is no longer active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*120), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now().Add(-time.Hour*24*50), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User last used access key 50 days ago and it is active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*120), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now().Add(-time.Hour*24*50), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0144": {
		{
			name: "User logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User never logged in, but used access key today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User logged in 100 days ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now().Add(-time.Hour*24*100), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "User last used access key 100 days ago but it is no longer active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*120), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now().Add(-time.Hour*24*100), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "User last used access key 100 days ago and it is active",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*120), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now().Add(-time.Hour*24*100), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0123": {
		{
			name: "IAM policy with no MFA required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Groups: []iam.Group{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"ec2:*"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed: builder.Build(),
									}
								}(),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "IAM policy with MFA required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Groups: []iam.Group{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"ec2:*"})
									sb.WithCondition("Bool", "aws:MultiFactorAuthPresent", []string{"true"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed: builder.Build(),
									}
								}(),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0142": {
		{
			name: "root user without mfa",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "other user without mfa",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("other", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user with mfa",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
						MFADevices: []iam.MFADevice{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsVirtual: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0140": {
		{
			name: "root user, never logged in",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user, logged in months ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("other", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now().Add(-time.Hour*24*90), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user, logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now().Add(-time.Hour), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "other user, logged in today",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("other", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.Time(time.Now().Add(-time.Hour), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0167": {
		{
			name: "Single active access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "One active, one inactive access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Two inactive keys",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Two active keys",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0056": {
		{
			name: "IAM with 1 password that can't be reused (min)",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             tunnelTypes.NewTestMetadata(),
					ReusePreventionCount: tunnelTypes.Int(1, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM with 5 passwords that can't be reused",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:             tunnelTypes.NewTestMetadata(),
					ReusePreventionCount: tunnelTypes.Int(5, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0141": {
		{
			name: "root user without access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			}}},
			expected: false,
		},
		{
			name: "other user without access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("other", tunnelTypes.NewTestMetadata()),
						AccessKeys: nil,
					},
				},
			}}},
			expected: false,
		},
		{
			name: "other user with access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("other", tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("BLAH", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user with inactive access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("BLAH", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "root user with active access key",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("root", tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("BLAH", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0143": {
		{
			name: "user without policies attached",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("example", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "user with a policy attached",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Name:     tunnelTypes.String("example", tunnelTypes.NewTestMetadata()),
						Policies: []iam.Policy{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Name:     tunnelTypes.String("another.policy", tunnelTypes.NewTestMetadata()),
								Document: iam.Document{
									Metadata: tunnelTypes.NewTestMetadata(),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0168": {
		{
			name:     "No certs",
			input:    state.State{AWS: aws.AWS{IAM: iam.IAM{}}},
			expected: false,
		},
		{
			name: "Valid cert",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Expiration: tunnelTypes.Time(time.Now().Add(time.Hour), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Expired cert",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				ServerCertificates: []iam.ServerCertificate{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Expiration: tunnelTypes.Time(time.Now().Add(-time.Hour), tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0058": {
		{
			name: "IAM password policy lowercase not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         tunnelTypes.NewTestMetadata(),
					RequireLowercase: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy lowercase required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         tunnelTypes.NewTestMetadata(),
					RequireLowercase: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0059": {
		{
			name: "IAM password policy numbers not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       tunnelTypes.NewTestMetadata(),
					RequireNumbers: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy numbers required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       tunnelTypes.NewTestMetadata(),
					RequireNumbers: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0060": {
		{
			name: "IAM password policy symbols not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       tunnelTypes.NewTestMetadata(),
					RequireSymbols: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy symbols required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:       tunnelTypes.NewTestMetadata(),
					RequireSymbols: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0061": {
		{
			name: "IAM password policy uppercase not required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         tunnelTypes.NewTestMetadata(),
					RequireUppercase: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "IAM password policy uppercase required",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:         tunnelTypes.NewTestMetadata(),
					RequireUppercase: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0146": {
		{
			name: "Access key created a month ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "Access key created 4 months ago",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				Users: []iam.User{
					{
						Metadata:   tunnelTypes.NewTestMetadata(),
						Name:       tunnelTypes.String("user", tunnelTypes.NewTestMetadata()),
						LastAccess: tunnelTypes.TimeUnresolvable(tunnelTypes.NewTestMetadata()),
						AccessKeys: []iam.AccessKey{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								AccessKeyId:  tunnelTypes.String("AKIACKCEVSQ6C2EXAMPLE", tunnelTypes.NewTestMetadata()),
								Active:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								CreationDate: tunnelTypes.Time(time.Now().Add(-time.Hour*24*30*4), tunnelTypes.NewTestMetadata()),
								LastAccess:   tunnelTypes.Time(time.Now(), tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0062": {
		{
			name: "Password expires in 99 days",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   tunnelTypes.NewTestMetadata(),
					MaxAgeDays: tunnelTypes.Int(99, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Password expires in 60 days",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:   tunnelTypes.NewTestMetadata(),
					MaxAgeDays: tunnelTypes.Int(60, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0063": {
		{
			name: "Minimum password length set to 8",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      tunnelTypes.NewTestMetadata(),
					MinimumLength: tunnelTypes.Int(8, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: true,
		},
		{
			name: "Minimum password length set to 15",
			input: state.State{AWS: aws.AWS{IAM: iam.IAM{
				PasswordPolicy: iam.PasswordPolicy{
					Metadata:      tunnelTypes.NewTestMetadata(),
					MinimumLength: tunnelTypes.Int(15, tunnelTypes.NewTestMetadata()),
				},
			}}},
			expected: false,
		},
	},
}
