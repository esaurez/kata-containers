// Copyright (c) 2016 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
//

package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/kata-containers/kata-containers/src/runtime/pkg/katautils"
	"github.com/kata-containers/kata-containers/src/runtime/pkg/oci"
	vc "github.com/kata-containers/kata-containers/src/runtime/virtcontainers"
	"github.com/kata-containers/kata-containers/src/runtime/virtcontainers/pkg/compatoci"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/sirupsen/logrus"
)

func validBundle(containerID, bundlePath string) (string, error) {
	// container ID MUST be provided.
	if containerID == "" {
		return "", fmt.Errorf("missing container ID")
	}

	// bundle path MUST be provided.
	if bundlePath == "" {
		return "", fmt.Errorf("missing bundle path")
	}

	// bundle path MUST be valid.
	fileInfo, err := os.Stat(bundlePath)
	if err != nil {
		return "", fmt.Errorf("invalid bundle path '%s': %s", bundlePath, err)
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("invalid bundle path '%s', it should be a directory", bundlePath)
	}

	resolved, err := katautils.ResolvePath(bundlePath)
	if err != nil {
		return "", err
	}

	return resolved, nil
}

func loadSpec(containerId, bundle string) (*specs.Spec, string, error) {
	// Checks the MUST and MUST NOT from OCI runtime specification
	bundlePath, err := validBundle(containerId, bundle)
	if err != nil {
		return nil, "", err
	}

	ociSpec, err := compatoci.ParseConfigJSON(bundlePath)
	if err != nil {
		return nil, "", err
	}

	return &ociSpec, bundlePath, nil
}

// This example creates and starts a single container sandbox,
// using cloud-hypervisor as the hypervisor and kata as the VM agent.
func Example_createAndStartClhSandbox(ociSpec *specs.Spec, bundlePath string) {
	cid := "sandbox-clh"

	container, err := oci.ContainerConfig(*ociSpec, bundlePath, cid, false)
	if err != nil {
		fmt.Printf("Could not create container config: %s", err)
		return
	}

	// Sets the hypervisor configuration.
	hypervisorConfig := vc.HypervisorConfig{
		HypervisorPath:     "/home/quique/src/cloud-hypervisor/target/debug/cloud-hypervisor",
		HypervisorPathList: []string{"/home/quique/src/cloud-hypervisor/target/release/cloud-hypervisor"},
		KernelPath:         "/usr/share/kata-containers/vmlinux.container",
		ImagePath:          "/usr/share/kata-containers/kata-containers.img",
		RootfsType:         "ext4",
		KernelParams: []vc.Param{
			{Key: "systemd.legacy_systemd_cgroup_controller", Value: "yes"},
			{Key: "systemd.unified_cgroup_hierarchy", Value: "0"},
			{Key: "agent.log", Value: "debug"},
			// initcall_debug
			{Key: "initcall_debug", Value: "1"},
		},
		NumVCPUsF:                1,
		DefaultMaxVCPUs:          8,
		MemorySize:               2048,
		MemSlots:                 10,
		MemOffset:                0,
		DefaultMaxMemorySize:     2048,
		EntropySource:            "/dev/urandom",
		EntropySourceList:        []string{"/dev/urandom"},
		DefaultBridges:           1,
		SharedFS:                 "virtio-fs",
		VirtioFSDaemon:           "/home/quique/src/virtiofsd/target/release/virtiofsd",
		VirtioFSDaemonList:       []string{"/home/quique/src/virtiofsd/target/release/virtiofsd"},
		VirtioFSCacheSize:        0,
		VirtioFSCache:            "auto",
		MemPrealloc:              false,
		HugePages:                false,
		IOMMU:                    false,
		IOMMUPlatform:            false,
		FileBackedMemRootDir:     "",
		Debug:                    true,
		DisableNestingChecks:     false,
		BlockDeviceDriver:        "virtio-blk",
		Msize9p:                  8192,
		ColdPlugVFIO:             "no-port",
		HotPlugVFIO:              "no-port",
		DisableVhostNet:          true,
		GuestHookPath:            "",
		DisableSeLinux:           false,
		DisableGuestSeLinux:      true,
		EnableAnnotations:        []string{".*"},
		VirtioFSQueueSize:        1024,
		VirtioFSExtraArgs:        []string{"--thread-pool-size=1", "-o", "announce_submounts"},
		NimbleVM:                 true,
		NimbleVMSharedMemorySize: 512 * 1024 * 1024, // 512MB
		NimbleVMNumQueues:        1,
		NimbleVMQueueSize:        2,
		NimbleVMSocketPath:       "/tmp/nimble.sock",
	}

	// Use kata default values for the agent.
	agConfig := vc.KataAgentConfig{
		EnableDebugConsole: true,
		DialTimeout:        60,
		KernelModules:      []string{"virtio_kata_driver"},
	}

	// The sandbox configuration:
	// - One container
	// - Hypervisor is QEMU
	// - Agent is kata
	sandboxConfig := vc.SandboxConfig{
		ID:               cid,
		HypervisorType:   vc.ClhHypervisor,
		HypervisorConfig: hypervisorConfig,

		AgentConfig: agConfig,

		Containers: []vc.ContainerConfig{container},
	}

	logger := logrus.NewEntry(logrus.New())
	logger.Logger.Level = logrus.DebugLevel
	for _, arg := range flag.Args() {
		if arg == "debug-logs" {
			logger.Logger.Level = logrus.DebugLevel
		}
	}

	vc.SetLogger(context.Background(), logger)

	// Create the sandbox
	s, err := vc.CreateSandbox(context.Background(), sandboxConfig, nil, nil)
	if err != nil {
		fmt.Printf("Could not create sandbox: %s", err)
		return
	}

	// Start the sandbox
	err = s.Start(context.Background())
	if err != nil {
		fmt.Printf("Could not start sandbox: %s", err)
	}

	fmt.Printf("Sandbox %s started\n", s.ID())

	s.Stop(context.Background(), true)
	s.Delete(context.Background())
}

func main() {
	// Get OCI spec location from command line
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <oci-spec>\n", os.Args[0])
		os.Exit(1)
	}

	// Load the OCI spec
	ociSpec, bundlePath, err := loadSpec("busybox", os.Args[1])
	if err != nil {
		fmt.Printf("Could not load OCI spec: %s", err)
		os.Exit(1)
	}

	Example_createAndStartClhSandbox(ociSpec, bundlePath)
}
