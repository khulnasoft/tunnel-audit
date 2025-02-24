package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/aws/ec2"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(awsEc2TestCases)
}

var awsEc2TestCases = testCases{
	"AVD-AWS-0124": {
		{
			name: "AWS VPC security group rule has no description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group rule has description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata:    tunnelTypes.NewTestMetadata(),
								Description: tunnelTypes.String("some description", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0099": {
		{
			name: "AWS VPC security group with no description provided",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group with default description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("Managed by Terraform", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group with proper description",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata:    tunnelTypes.NewTestMetadata(),
						Description: tunnelTypes.String("some proper description", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0008": {
		{
			name: "Autoscaling unencrypted root block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Encrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Autoscaling unencrypted EBS block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								Encrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Autoscaling encrypted root and EBS block devices",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  tunnelTypes.NewTestMetadata(),
							Encrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
						EBSBlockDevices: []*ec2.BlockDevice{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								Encrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0130": {
		{
			name: "Launch configuration with optional tokens",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     tunnelTypes.NewTestMetadata(),
							HttpTokens:   tunnelTypes.String("optional", tunnelTypes.NewTestMetadata()),
							HttpEndpoint: tunnelTypes.String("enabled", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch template with optional tokens",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: tunnelTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								Metadata:     tunnelTypes.NewTestMetadata(),
								HttpTokens:   tunnelTypes.String("optional", tunnelTypes.NewTestMetadata()),
								HttpEndpoint: tunnelTypes.String("enabled", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch configuration with required tokens",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     tunnelTypes.NewTestMetadata(),
							HttpTokens:   tunnelTypes.String("required", tunnelTypes.NewTestMetadata()),
							HttpEndpoint: tunnelTypes.String("enabled", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0129": {
		{
			name: "Launch template with sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: tunnelTypes.NewTestMetadata(),
							UserData: tunnelTypes.String(`
							export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
							export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
							export AWS_DEFAULT_REGION=us-west-2
							`, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch template with no sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: tunnelTypes.NewTestMetadata(),
							UserData: tunnelTypes.String(`
							export GREETING=hello
							`, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0131": {
		{
			name: "encrypted block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "unencrypted block device",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						RootBlockDevice: &ec2.BlockDevice{
							Encrypted: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
	},
	"AVD-AWS-0026": {
		{
			name: "unencrypted EBS volume",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "encrypted EBS volume",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0027": {
		{
			name: "EC2 volume missing KMS key",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "EC2 volume encrypted with KMS key",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: tunnelTypes.NewTestMetadata(),
							KMSKeyID: tunnelTypes.String("some-kms-key", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0028": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     tunnelTypes.NewTestMetadata(),
							HttpTokens:   tunnelTypes.String("optional", tunnelTypes.NewTestMetadata()),
							HttpEndpoint: tunnelTypes.String("enabled", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     tunnelTypes.NewTestMetadata(),
							HttpTokens:   tunnelTypes.String("required", tunnelTypes.NewTestMetadata()),
							HttpEndpoint: tunnelTypes.String("disabled", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0101": {
		{
			name: "default AWS VPC",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						IsDefault: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "vpc but not default AWS VPC",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						IsDefault: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
		{
			name:     "no default AWS VPC",
			input:    state.State{AWS: aws.AWS{EC2: ec2.EC2{}}},
			expected: false,
		},
	},
	"AVD-AWS-0102": {
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("-1", tunnelTypes.NewTestMetadata()),
								Action:   tunnelTypes.String("allow", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with protocol set to all",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("all", tunnelTypes.NewTestMetadata()),
								Action:   tunnelTypes.String("allow", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with tcp protocol",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Protocol: tunnelTypes.String("tcp", tunnelTypes.NewTestMetadata()),
								Type:     tunnelTypes.String("egress", tunnelTypes.NewTestMetadata()),
								Action:   tunnelTypes.String("allow", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0104": {
		{
			name: "AWS VPC security group rule with wildcard address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								CIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC security group rule with private address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						EgressRules: []ec2.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								CIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0105": {
		{
			name: "AWS VPC network ACL rule with wildcard address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Type:     tunnelTypes.String(ec2.TypeIngress, tunnelTypes.NewTestMetadata()),
								Action:   tunnelTypes.String(ec2.ActionAllow, tunnelTypes.NewTestMetadata()),
								Protocol: tunnelTypes.StringTest("tcp"),
								FromPort: tunnelTypes.IntTest(22),
								ToPort:   tunnelTypes.IntTest(22),
								CIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC network ACL rule with private address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				NetworkACLs: []ec2.NetworkACL{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Rules: []ec2.NetworkACLRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								Type:     tunnelTypes.String(ec2.TypeIngress, tunnelTypes.NewTestMetadata()),
								Action:   tunnelTypes.String(ec2.ActionAllow, tunnelTypes.NewTestMetadata()),
								CIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0107": {
		{
			name: "AWS VPC ingress security group rule with wildcard address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								CIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("0.0.0.0/0", tunnelTypes.NewTestMetadata()),
								},
								Protocol: tunnelTypes.StringTest("tcp"),
								FromPort: tunnelTypes.IntTest(22),
								ToPort:   tunnelTypes.IntTest(22),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "AWS VPC ingress security group rule with private address",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				SecurityGroups: []ec2.SecurityGroup{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						IngressRules: []ec2.SecurityGroupRule{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								CIDRs: []tunnelTypes.StringValue{
									tunnelTypes.String("10.0.0.0/16", tunnelTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0164": {
		{
			name: "Subnet with public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Subnets: []ec2.Subnet{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						MapPublicIpOnLaunch: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Subnet without public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Subnets: []ec2.Subnet{
					{
						Metadata:            tunnelTypes.NewTestMetadata(),
						MapPublicIpOnLaunch: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0009": {
		{
			name: "Launch configuration with public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						AssociatePublicIP: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch configuration without public access",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata:          tunnelTypes.NewTestMetadata(),
						AssociatePublicIP: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0029": {
		{
			name: "positive result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						UserData: tunnelTypes.String(`<<EOF
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						EOF`, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "negative result",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						UserData: tunnelTypes.String(`<<EOF
						export GREETING=hello
						EOF`, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0122": {
		{
			name: "Launch configuration with sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						UserData: tunnelTypes.String(`
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						`, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Launch configuration with no sensitive info in user data",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						UserData: tunnelTypes.String(`
						export GREETING=hello
						`, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0178": {
		{
			name: "VPC without flow logs enabled",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						ID:              tunnelTypes.String("vpc-12345678", tunnelTypes.NewTestMetadata()),
						FlowLogsEnabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "VPC with flow logs enabled",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata:        tunnelTypes.NewTestMetadata(),
						ID:              tunnelTypes.String("vpc-12345678", tunnelTypes.NewTestMetadata()),
						FlowLogsEnabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AWS-0173": {
		{
			name: "default sg restricts all",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								IsDefault:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								IngressRules: nil,
								EgressRules:  nil,
							},
						},
					},
				},
			}}},
			expected: false,
		},
		{
			name: "default sg allows ingress",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:  tunnelTypes.NewTestMetadata(),
								IsDefault: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								IngressRules: []ec2.SecurityGroupRule{
									{},
								},
								EgressRules: nil,
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "default sg allows egress",
			input: state.State{AWS: aws.AWS{EC2: ec2.EC2{
				VPCs: []ec2.VPC{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						SecurityGroups: []ec2.SecurityGroup{
							{
								Metadata:     tunnelTypes.NewTestMetadata(),
								IsDefault:    tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
								IngressRules: nil,
								EgressRules: []ec2.SecurityGroupRule{
									{},
								},
							},
						},
					},
				},
			}}},
			expected: true,
		},
	},
}
