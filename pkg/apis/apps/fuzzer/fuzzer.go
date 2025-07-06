/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package fuzzer

import (
	"fmt"

	"sigs.k8s.io/randfill"

	"k8s.io/apimachinery/pkg/runtime"
	runtimeserializer "k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/kubernetes/pkg/api/legacyscheme"
	"k8s.io/kubernetes/pkg/apis/apps"
)

// int32Ptr returns a pointer to an int32 value.
func int32Ptr(i int32) *int32 { return &i }

// Valid deployment strategy types used in fuzzing.
var deploymentStrategyTypes = []apps.DeploymentStrategyType{
	apps.RecreateDeploymentStrategyType,
	apps.RollingUpdateDeploymentStrategyType,
}

// Valid daemon set update strategy types used in fuzzing.
var daemonSetUpdateStrategyTypes = []apps.DaemonSetUpdateStrategyType{
	apps.RollingUpdateDaemonSetStrategyType,
	apps.OnDeleteDaemonSetStrategyType,
}

// NOTE:
// Kubernetes' Scheme.Default only applies to top-level API types.
// Subresource types (e.g., DeploymentSpec, DaemonSetSpec) must be manually defaulted inside fuzzers.
var Funcs = func(codecs runtimeserializer.CodecFactory) []interface{} {
	return []interface{}{
		func(r *apps.ControllerRevision, c randfill.Continue) {
			c.FillNoCustom(r)
			r.Data = runtime.RawExtension{
				Raw: []byte(`{"apiVersion":"unknown.group/unknown","kind":"Something","someKey":"someValue"}`),
			}
			legacyscheme.Scheme.Default(r)
		},
		func(s *apps.StatefulSet, c randfill.Continue) {
			c.FillNoCustom(s)
			legacyscheme.Scheme.Default(s)
		},
		func(d *apps.Deployment, c randfill.Continue) {
			c.FillNoCustom(d)
			legacyscheme.Scheme.Default(d)
		},
		func(spec *apps.DeploymentSpec, c randfill.Continue) {
			c.FillNoCustom(spec)

			if spec.RevisionHistoryLimit == nil {
				spec.RevisionHistoryLimit = int32Ptr(c.Rand.Int31())
			}
			if spec.ProgressDeadlineSeconds == nil {
				spec.ProgressDeadlineSeconds = int32Ptr(c.Rand.Int31())
			}
		},
		func(strategy *apps.DeploymentStrategy, c randfill.Continue) {
			c.FillNoCustom(strategy)
			strategy.Type = deploymentStrategyTypes[c.Rand.Intn(len(deploymentStrategyTypes))]

			if strategy.Type == apps.RollingUpdateDeploymentStrategyType {
				rolling := apps.RollingUpdateDeployment{}
				if c.Bool() {
					rolling.MaxUnavailable = intstr.FromInt32(c.Rand.Int31())
					rolling.MaxSurge = intstr.FromInt32(c.Rand.Int31())
				} else {
					rolling.MaxSurge = intstr.FromString(fmt.Sprintf("%d%%", c.Rand.Int31()))
				}
				strategy.RollingUpdate = &rolling
			} else {
				strategy.RollingUpdate = nil
			}
		},
		func(ds *apps.DaemonSet, c randfill.Continue) {
			c.FillNoCustom(ds)
			legacyscheme.Scheme.Default(ds)
		},
		func(spec *apps.DaemonSetSpec, c randfill.Continue) {
			c.FillNoCustom(spec)
			if spec.RevisionHistoryLimit == nil {
				spec.RevisionHistoryLimit = int32Ptr(c.Rand.Int31())
			}
		},
		func(strategy *apps.DaemonSetUpdateStrategy, c randfill.Continue) {
			c.FillNoCustom(strategy)
			strategy.Type = daemonSetUpdateStrategyTypes[c.Rand.Intn(len(daemonSetUpdateStrategyTypes))]

			if strategy.Type == apps.RollingUpdateDaemonSetStrategyType {
				rolling := apps.RollingUpdateDaemonSet{}
				if c.Bool() {
					if c.Bool() {
						rolling.MaxUnavailable = intstr.FromInt32(c.Rand.Int31())
						rolling.MaxSurge = intstr.FromInt32(c.Rand.Int31())
					} else {
						rolling.MaxSurge = intstr.FromString(fmt.Sprintf("%d%%", c.Rand.Int31()))
					}
				}
				strategy.RollingUpdate = &rolling
			} else {
				strategy.RollingUpdate = nil
			}
		},
		func(rs *apps.ReplicaSet, c randfill.Continue) {
			c.FillNoCustom(rs)
			legacyscheme.Scheme.Default(rs)
		},
	}
}
