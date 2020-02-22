// +build windows

package server

import (
	"os"
	"os/signal"
	"syscall"
	"time"

	v1 "k8s.io/api/core/v1"
	types "k8s.io/apimachinery/pkg/types"
	"k8s.io/klog"
)

type WindowsRedirector struct {
	Server *Server
}

func makeRedirectorInt(server *Server) RedirectorInt {
	return &WindowsRedirector{Server: server}
}

var podMap = make(map[types.UID]string)

// Redirect metadata endpoint call to NMI pod by applying route policy
// to all the existing pods and watch for new pod creation to apply route
// policy when the new pod is created.
func (s *WindowsRedirector) RedirectMetadataEndpoint() {
	exit := make(chan struct{})
	s.Server.PodClient.Start(exit)
	klog.V(6).Infof("Pod client started")

	s.ApplyRoutePolicyForExistingPods()
	go s.Sync()
}

func (s *WindowsRedirector) Sync() {
	klog.Info("Sync thread started.")

	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGTERM, syscall.SIGINT)
	s.Server.Initialized = true

	var pod *v1.Pod

	for {
		select {
		case <-signalChan:
			s.DeleteRoutePolicyForExistingPods()
			break
		case pod = <-s.Server.PodObjChannel:
			klog.V(6).Infof("Received event: %s", pod)

			if s.Server.NodeName == pod.Spec.NodeName && s.Server.HostIP != pod.Status.PodIP {
				if podIP, podExist := podMap[pod.UID]; podExist {
					klog.Infof("Start to delete: Pod UID and Pod Name:%s %s", pod.UID, pod.Name)
					DeleteEndpointRoutePolicy(podIP, s.Server.MetadataIP)
					delete(podMap, pod.UID)
				} else {
					klog.Infof("Start to add: Pod UID and Pod Name:%s %s", pod.UID, pod.Name)
					podMap[pod.UID] = pod.Status.PodIP
					ApplyEndpointRoutePolicy(pod.Status.PodIP, s.Server.MetadataIP, s.Server.MetadataPort, s.Server.HostIP, s.Server.NMIPort)
				}
			}
		}
	}
}

func (s *WindowsRedirector) ApplyRoutePolicyForExistingPods() {
	klog.Info("Apply route policy for existing pods started.")

	listPods, err := s.Server.PodClient.ListPods()
	if err != nil {
		klog.Error(err)
	}

	for _, podItem := range listPods {
		if podItem.Spec.NodeName == s.Server.NodeName && podItem.Status.PodIP != "" && podItem.Status.PodIP != s.Server.HostIP {
			klog.Infof("Get Host IP, Node Name and Pod IP: \n %s %s %s \n", podItem.Status.HostIP, podItem.Spec.NodeName, podItem.Status.PodIP)
			ApplyEndpointRoutePolicy(podItem.Status.PodIP, s.Server.MetadataIP, s.Server.MetadataPort, s.Server.HostIP, s.Server.NMIPort)
		}
	}
}

func (s *WindowsRedirector) DeleteRoutePolicyForExistingPods() {
	klog.Info("Received SIGTERM, shutting down")
	klog.Info("Delete route policy for existing pods started.")

	exitCode := 0

	listPods, err := s.Server.PodClient.ListPods()
	if err != nil {
		klog.Error(err)
		exitCode = 1
	}

	for _, podItem := range listPods {
		if podItem.Spec.NodeName == s.Server.NodeName {
			klog.Infof("Get Host IP, Node Name and Pod IP: \n %s %s %s \n", podItem.Status.HostIP, podItem.Spec.NodeName, podItem.Status.PodIP)
			DeleteEndpointRoutePolicy(podItem.Status.PodIP, s.Server.MetadataIP)
		}
	}

	// Wait for pod to delete
	klog.Info("Handled termination, awaiting pod deletion")
	time.Sleep(10 * time.Second)

	klog.Infof("Exiting with %v", exitCode)
	os.Exit(exitCode)
}
