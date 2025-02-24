package main

import (
	"fmt"
	"os"

	"github.com/open-policy-agent/opa/cmd"

	"github.com/khulnasoft/tunnel-audit/pkg/rego"
	_ "github.com/khulnasoft/tunnel/pkg/iac/rego" // register Built-in Functions from Tunnel
)

func main() {
	rego.RegisterBuiltins()
	// runs: opa test lib/ checks/
	if err := cmd.RootCommand.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
