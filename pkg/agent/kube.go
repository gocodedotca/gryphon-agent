package agent

import (
	"regexp"
	"strings"
)

// The grammar Kubernetes holds names to, shared by the server, which refuses
// anything else on save, and the agent, which refuses it again before a name
// goes anywhere near a URL path.
var (
	// A namespace is a DNS-1123 label.
	kubeLabel = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	// Most other objects -- workloads, CronJobs -- are DNS-1123 subdomains.
	kubeSubdomain = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)
)

// ValidKubeNamespace reports whether s could name a Kubernetes namespace.
func ValidKubeNamespace(s string) bool {
	return len(s) <= 63 && kubeLabel.MatchString(s)
}

// ValidKubeName reports whether s could name a workload or a CronJob.
func ValidKubeName(s string) bool {
	return len(s) <= 253 && kubeSubdomain.MatchString(s)
}

// MaxKubeSelector bounds a label selector.
const MaxKubeSelector = 1024

// KubeSelectorProblem is what is wrong with a label selector, or "". Only its
// size and characters: the API server parses selectors and says what is wrong
// with one, and a second parser here would be a second opinion that can
// disagree with the one that counts.
func KubeSelectorProblem(s string) string {
	if len(s) > MaxKubeSelector {
		return "is longer than 1024 characters"
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "contains a control character"
	}
	return ""
}

// The kinds a k8s-workload check reads, as ParamKind spells them.
const (
	KindDeployment  = "deployment"
	KindStatefulSet = "statefulset"
	KindDaemonSet   = "daemonset"
)

// KubeWorkloadKinds is every kind a k8s-workload check reads, in the order a
// form offers them.
var KubeWorkloadKinds = []string{KindDeployment, KindStatefulSet, KindDaemonSet}
