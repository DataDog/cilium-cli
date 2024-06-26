// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package builder

import (
	"github.com/cilium/cilium-cli/utils/features"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"
	tests2 "github.com/cilium/cilium/cilium-cli/connectivity/tests"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type clientEgressL7SetHeader struct{}

func (t clientEgressL7SetHeader) build(ct *check2.ConnectivityTest, templates map[string]string) {
	// Test L7 HTTP with a header replace set in the policy
	newTest("client-egress-l7-set-header", ct).
		WithFeatureRequirements(features.RequireEnabled(features.L7Proxy)).
		WithFeatureRequirements(features.RequireEnabled(features.SecretBackendK8s)).
		WithSecret(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name: "header-match",
			},
			Data: map[string][]byte{
				"value": []byte("Bearer 123456"),
			},
		}).
		WithCiliumPolicy(templates["clientEgressL7HTTPMatchheaderSecretYAML"]). // L7 allow policy with HTTP introspection (POST only)
		WithScenarios(
			tests2.PodToPodWithEndpoints(tests2.WithMethod("POST"), tests2.WithPath("auth-header-required"), tests2.WithDestinationLabelsOption(map[string]string{"other": "echo"})),
			tests2.PodToPodWithEndpoints(tests2.WithMethod("POST"), tests2.WithPath("auth-header-required"), tests2.WithDestinationLabelsOption(map[string]string{"first": "echo"})),
		).
		WithExpectations(func(a *check2.Action) (egress, ingress check2.Result) {
			if a.Source().HasLabel("other", "client") && // Only client2 has the header policy.
				(a.Destination().Port() == 8080) { // port 8080 is traffic to echo Pod.
				return check2.ResultOK, check2.ResultNone
			}
			return check2.ResultCurlHTTPError, check2.ResultNone // if the header is not set the request will get a 401
		})
}
