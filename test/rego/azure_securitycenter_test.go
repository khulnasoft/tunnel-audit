package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/securitycenter"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureSecurityCenterTestCases)
}

var azureSecurityCenterTestCases = testCases{
	"AVD-AZU-0044": {
		{
			name: "Security center alert nofifications disabled",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata:                 tunnelTypes.NewTestMetadata(),
						EnableAlertNotifications: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security center alert nofifications enabled",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata:                 tunnelTypes.NewTestMetadata(),
						EnableAlertNotifications: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0045": {
		{
			name: "Security center set with free subscription",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tier:     tunnelTypes.String(securitycenter.TierFree, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Security center set with standard subscription",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Subscriptions: []securitycenter.SubscriptionPricing{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Tier:     tunnelTypes.String(securitycenter.TierStandard, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0046": {
		{
			name: "Contact's phone number missing",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Phone:    tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Contact's phone number provided",
			input: state.State{Azure: azure.Azure{SecurityCenter: securitycenter.SecurityCenter{
				Contacts: []securitycenter.Contact{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Phone:    tunnelTypes.String("+1-555-555-5555", tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
}
