package test

import (
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure"
	"github.com/khulnasoft/tunnel/pkg/iac/providers/azure/appservice"
	"github.com/khulnasoft/tunnel/pkg/iac/state"
	tunnelTypes "github.com/khulnasoft/tunnel/pkg/iac/types"
)

func init() {
	addTests(azureAppServiceTestCases)
}

var azureAppServiceTestCases = testCases{
	"AVD-AZU-0002": {
		{
			name: "App service identity not registered",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Identity: struct{ Type tunnelTypes.StringValue }{
							Type: tunnelTypes.String("", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "App service identity registered",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Identity: struct{ Type tunnelTypes.StringValue }{
							Type: tunnelTypes.String("UserAssigned", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0003": {
		{
			name: "App service authentication disabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Authentication: struct{ Enabled tunnelTypes.BoolValue }{
							Enabled: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "App service authentication enabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Authentication: struct{ Enabled tunnelTypes.BoolValue }{
							Enabled: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0005": {
		{
			name: "HTTP2 disabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       tunnelTypes.BoolValue
							MinimumTLSVersion tunnelTypes.StringValue
						}{
							EnableHTTP2: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "HTTP2 enabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       tunnelTypes.BoolValue
							MinimumTLSVersion tunnelTypes.StringValue
						}{
							EnableHTTP2: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0004": {
		{
			name: "Function app doesn't enforce HTTPS",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						HTTPSOnly: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Function app enforces HTTPS",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{
					{
						Metadata:  tunnelTypes.NewTestMetadata(),
						HTTPSOnly: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0001": {
		{
			name: "App service client certificate disabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableClientCert: tunnelTypes.Bool(false, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: true,
		},
		{
			name: "App service client certificate enabled",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata:         tunnelTypes.NewTestMetadata(),
						EnableClientCert: tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
					},
				},
			}}},
			expected: false,
		},
	},
	"AVD-AZU-0006": {
		{
			name: "Minimum TLS version TLS1_0",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       tunnelTypes.BoolValue
							MinimumTLSVersion tunnelTypes.StringValue
						}{
							EnableHTTP2:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							MinimumTLSVersion: tunnelTypes.String("1.0", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: true,
		},
		{
			name: "Minimum TLS version TLS1_2",
			input: state.State{Azure: azure.Azure{AppService: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: tunnelTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       tunnelTypes.BoolValue
							MinimumTLSVersion tunnelTypes.StringValue
						}{
							EnableHTTP2:       tunnelTypes.Bool(true, tunnelTypes.NewTestMetadata()),
							MinimumTLSVersion: tunnelTypes.String("1.2", tunnelTypes.NewTestMetadata()),
						},
					},
				},
			}}},
			expected: false,
		},
	},
}
