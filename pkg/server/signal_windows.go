// +build windows

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

package server

import (
	"syscall"

	"github.com/containerd/containerd/oci"
)

const (
	// SysMS_NOEXEC is the Windows representation of unix.MS_NOEXEC
	SysMS_NOEXEC = 0x8
	// SysMS_NOSUID is the Windows representation of unix.MS_NOSUID
	SysMS_NOSUID = 0x2
	// SysMS_NODEV is the Windows representation of unix.MS_NODEV
	SysMS_NODEV = 0x4
)

func getSysKillSignal(spec *oci.Spec) syscall.Signal {
	if spec.Linux != nil {
		// Windows representation of unix.SIGKILL
		return syscall.Signal(0x9)
	}
	// Windows container equivalent of unix.SIGKILL
	return syscall.Signal(0x6)
}

func getSysTermSignal(spec *oci.Spec) syscall.Signal {
	if spec.Linux != nil {
		// Windows representation of unix.SIGTERM
		return syscall.Signal(0xf)
	}
	// Windows container equivalent of unix.SIGTERM
	return syscall.Signal(0x0)
}
