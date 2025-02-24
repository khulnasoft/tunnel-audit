package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/digitalocean"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/digitalocean/spaces"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(digitalOceanSpacesTestCases)
}

var digitalOceanSpacesTestCases = testCases{
	"AVD-DIG-0006": {
		{
			name: "Space bucket with public read ACL",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ACL:      tunnelTypes.String("public-read", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket object with public read ACL",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ACL:      tunnelTypes.String("private", tunnelTypes.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								ACL:      tunnelTypes.String("public-read", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket and bucket object with private ACL",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						ACL:      tunnelTypes.String("private", tunnelTypes.NewTestMetadata()),
						Objects: []spaces.Object{
							{
								Metadata: tunnelTypes.NewTestMetadata(),
								ACL:      tunnelTypes.String("private", tunnelTypes.NewTestMetadata()),
							},
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0009": {
		{
			name: "Space bucket force destroy enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						ForceDestroy: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket force destroy disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata:     tunnelTypes.NewTestMetadata(),
						ForceDestroy: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-DIG-0007": {
		{
			name: "Space bucket versioning disabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: spaces.Versioning{
							Metadata: tunnelTypes.NewTestMetadata(),
							Enabled:  tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Space bucket versioning enabled",
			input: state.State{DigitalOcean: digitalocean.DigitalOcean{Spaces: spaces.Spaces{
				Buckets: []spaces.Bucket{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Versioning: spaces.Versioning{
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
