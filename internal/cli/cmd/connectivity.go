// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"fmt"
	corev1 "k8s.io/api/core/v1"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"syscall"

	"github.com/cilium/cilium-cli/connectivity"
	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"

	"github.com/spf13/cobra"
)

func newCmdConnectivity() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "connectivity",
		Short: "Connectivity troubleshooting",
		Long:  ``,
	}

	cmd.AddCommand(newCmdConnectivityTest())

	return cmd
}

var params = check.Parameters{
	Writer:            os.Stdout,
	GlobalTolerations: []corev1.Toleration{},
}
var tests []string
var podTolerations []string

func newCmdConnectivityTest() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Validate connectivity in cluster",
		Long:  ``,
		RunE: func(cmd *cobra.Command, args []string) error {

			for _, test := range tests {
				if strings.HasPrefix(test, "!") {
					rgx, err := regexp.Compile(strings.TrimPrefix(test, "!"))
					if err != nil {
						return fmt.Errorf("Test filter: %w", err)
					}
					params.SkipTests = append(params.SkipTests, rgx)
				} else {
					rgx, err := regexp.Compile(test)
					if err != nil {
						return fmt.Errorf("Test filter: %w", err)
					}
					params.RunTests = append(params.RunTests, rgx)
				}
			}

			// Validate toleration string
			var allowedEffects = []string{"NoSchedule", "NoExecute", "PreferNoSchedule"}
			for _, toleration := range podTolerations {
				tolerationString := strings.Split(toleration, ":")
				if len(tolerationString) < 2 {
					return fmt.Errorf("invalid format: %s, toleration string should be of format key1=value1:effect", toleration)
				}
				validEffect := false
				for _, e := range allowedEffects {
					if tolerationString[1] == e {
						validEffect = true
					}
				}
				if !validEffect {
					return fmt.Errorf("invalid effect: %s, toleration effect should be either NoSchedule, NoExecute or PreferNoSchedule", tolerationString[1])
				}
				kv := strings.Split(tolerationString[0], "=")
				if len(kv) < 2 || len(kv[0]) == 0 || len(kv[1]) == 0 {
					return fmt.Errorf("invalid key value pair: %s", tolerationString[0])
				}
				params.GlobalTolerations = append(params.GlobalTolerations, corev1.Toleration{
					Key:      kv[0],
					Operator: "Equal",
					Value:    kv[1],
					Effect:   corev1.TaintEffect(tolerationString[1]),
				})
			}

			// Instantiate the test harness.
			cc, err := check.NewConnectivityTest(k8sClient, params)

			if err != nil {
				return err
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			go func() {
				<-ctx.Done()
				cc.Log("Interrupt received, cancelling tests...")
			}()

			if err := connectivity.Run(ctx, cc); err != nil {
				fatalf("Connectivity test failed: %s", err)
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&params.SingleNode, "single-node", false, "Limit to tests able to run on a single node")
	cmd.Flags().BoolVar(&params.PrintFlows, "print-flows", false, "Print flow logs for each test")
	cmd.Flags().DurationVar(&params.PostTestSleepDuration, "post-test-sleep", 0, "Wait time after each test before next test starts")
	cmd.Flags().BoolVar(&params.ForceDeploy, "force-deploy", false, "Force re-deploying test artifacts")
	cmd.Flags().BoolVar(&params.Hubble, "hubble", true, "Automatically use Hubble for flow validation & troubleshooting")
	cmd.Flags().StringVar(&params.HubbleServer, "hubble-server", "localhost:4245", "Address of the Hubble endpoint for flow validation")
	cmd.Flags().StringVarP(&params.CiliumNamespace, "namespace", "n", "kube-system", "Namespace Cilium is running in")
	cmd.Flags().StringVar(&params.TestNamespace, "test-namespace", defaults.ConnectivityCheckNamespace, "Namespace to perform the connectivity test in")
	cmd.Flags().StringVar(&params.AgentDaemonSetName, "agent-daemonset-name", defaults.AgentDaemonSetName, "Name of cilium agent daemonset")
	cmd.Flags().StringVar(&params.MultiCluster, "multi-cluster", "", "Test across clusters to given context")
	cmd.Flags().StringVar(&contextName, "context", "", "Kubernetes configuration context")
	cmd.Flags().StringSliceVar(&tests, "test", []string{}, "Run tests that match one of the given regular expressions, skip tests by starting the expression with '!', target Scenarios with e.g. '/pod-to-cidr'")
	cmd.Flags().StringSliceVar(&podTolerations, "pod-tolerations", []string{}, "Tolerations to add to test workloads and client pods. Comma separated values of the format key1=value1:effect, effect can be NoSchedule, NoExecute or PreferNoSchedule")
	cmd.Flags().StringVar(&params.FlowValidation, "flow-validation", check.FlowValidationModeWarning, "Enable Hubble flow validation { disabled | warning | strict }")
	cmd.Flags().BoolVar(&params.AllFlows, "all-flows", false, "Print all flows during flow validation")
	cmd.Flags().BoolVarP(&params.Verbose, "verbose", "v", false, "Show informational messages and don't buffer any lines")
	cmd.Flags().BoolVarP(&params.Debug, "debug", "d", false, "Show debug messages")
	cmd.Flags().BoolVarP(&params.PauseOnFail, "pause-on-fail", "p", false, "Pause execution on test failure")

	return cmd
}
