// +build windows

/*
Copyright 2018 The containerd Authors.

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

package main

import (
	"github.com/Microsoft/go-winio/pkg/etwlogrus"
	"github.com/sirupsen/logrus"
)

func initLoggers() error {
	// Provider ID: {D65583AF-C0FC-5DE9-732E-8B31CCF3EC07}
	// Hook isn't closed explicitly, as it will exist until process exit.
	hook, err := etwlogrus.NewHook("Microsoft.Virtualization.CRIContainerD")
	if err != nil {
		return err
	}

	logrus.AddHook(hook)
	return nil
}
