//go:build windows
// +build windows

package server

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Azure/aad-pod-identity/pkg/metrics"
	v1 "k8s.io/api/core/v1"
	"k8s.io/klog/v2"
)

// WindowsRedirector returns sync function for windows redirector
func WindowsRedirector(server *Server, subRoutineDone <-chan struct{}) func(*Server, chan<- struct{}, <-chan struct{}) {
	server.PodClient.Start(subRoutineDone)
	klog.V(6).Infof("Pod client started")

	return func(server *Server, subRoutineDone chan<- struct{}, mainRoutineDone <-chan struct{}) {
		Sync(server, subRoutineDone, mainRoutineDone)
	}
}

// LinuxRedirector returns sync function for linux redirector
func LinuxRedirector(server *Server, subRoutineDone <-chan struct{}) func(*Server, chan<- struct{}, <-chan struct{}) {
	panic("Linux Redirector is not applicable")
}

// Sync methods watches pod creation and applies policy to that
func Sync(server *Server, subRoutineDone chan<- struct{}, mainRoutineDone <-chan struct{}) {
	klog.Info("Sync thread started.")

	ApplyRoutePolicyForExistingPods(server)

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	server.Initialized = true

	var pod *v1.Pod

	for {
		select {
		case <-signalChan:
			DeleteRoutePolicyForExistingPods(server)
			close(subRoutineDone)
		case <-mainRoutineDone:
			DeleteRoutePolicyForExistingPods(server)
			close(subRoutineDone)
		case pod = <-server.PodObjChannel:
			if pod.Status.PodIP != "" && server.NodeName == pod.Spec.NodeName && server.HostIP != pod.Status.PodIP {
				klog.Infof("Start to add: Pod UID and Pod Name:%s %s", pod.UID, pod.Name)
				err, t := ApplyEndpointRoutePolicy(pod.Status.PodIP, server.MetadataIP, server.MetadataPort, server.HostIP, server.NMIPort)
				uploadIPRoutePolicyMetrics(err, server, pod.Status.PodIP)

				if err != nil {
					klog.Errorf("Failed to apply endpoint route policy: %s", err)
					if t != NotFound {
						RoutePolicySelfHeal(server)
					}
				} else {
					klog.Infof("Completed apply route policy for pod ip %s", pod.Status.PodIP)
				}
			}
		}
	}
}

// Route policy self heal
func RoutePolicySelfHeal(server *Server) {
	// Phase 1: we will just apply route policy for all the existing pod.
	// Phase 2: we will pick up the pods without correct routing policy and then apply route poliy to them.
	time.Sleep(10 * time.Second)
	ApplyRoutePolicyForExistingPods(server)
}

// ApplyRoutePolicyForExistingPods applies the route policy for existing pods
func ApplyRoutePolicyForExistingPods(server *Server) {
	klog.Info("Apply route policy for existing pods.")

	listPods, err := server.PodClient.ListPods()
	if err != nil {
		klog.Errorf("Failed to list pods when applying route policy for all existing pods: %+v", err)
	}

	for _, podItem := range listPods {
		if podItem.Spec.NodeName == server.NodeName && podItem.Status.PodIP != "" && podItem.Status.PodIP != server.HostIP {
			klog.Infof("Get Host IP, Node Name and Pod IP: %s %s %s", podItem.Status.HostIP, podItem.Spec.NodeName, podItem.Status.PodIP)
			err, _ := ApplyEndpointRoutePolicy(podItem.Status.PodIP, server.MetadataIP, server.MetadataPort, server.HostIP, server.NMIPort)
			uploadIPRoutePolicyMetrics(err, server, podItem.Status.PodIP)
			if err != nil {
				klog.Errorf("Failed to apply endpoint route policy when applying route policy for pod: %+v", err)
			}
		}
	}

	klog.Info("Completed try to apply route policy for existing pods.")
}

// DeleteRoutePolicyForExistingPods deletes the route policy for existing pods
func DeleteRoutePolicyForExistingPods(server *Server) {
	klog.Info("Received SIGTERM, shutting down")
	klog.Info("Delete route policy for existing pods started.")

	exitCode := 0

	listPods, err := server.PodClient.ListPods()
	if err != nil {
		klog.Errorf("Failed to list pods when deleting route policy for all existing pods: %+v", err)
		exitCode = 1
	}

	for _, podItem := range listPods {
		if podItem.Spec.NodeName == server.NodeName {
			klog.Infof("Get Host IP, Node Name and Pod IP: \n %s %s %s \n", podItem.Status.HostIP, podItem.Spec.NodeName, podItem.Status.PodIP)
			err, _ := DeleteEndpointRoutePolicy(podItem.Status.PodIP, server.MetadataIP)
			uploadIPRoutePolicyMetrics(err, server, podItem.Status.PodIP)
			if err != nil {
				klog.Errorf("Failed to delete endpoint route policy when deleting route policy for all existing pods: %+v", err)
			}
		}
	}

	// wait for pod to delete
	klog.Info("Handled termination, awaiting pod deletion")
	time.Sleep(10 * time.Second)

	klog.Infof("Exiting with %v", exitCode)
	os.Exit(exitCode)
}

func uploadIPRoutePolicyMetrics(err error, server *Server, podIP string) {
	if err != nil {
		server.Reporter.ReportIPRoutePolicyOperation(
			podIP, server.NodeName, metrics.NMIHostPolicyApplyFailedCountM.M(1))
	}
	server.Reporter.ReportIPRoutePolicyOperation(
		podIP, server.NodeName, metrics.NMIHostPolicyApplyCountM.M(1))
}
