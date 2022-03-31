package probes

import (
	"encoding/json"
	"net/http"
	"strings"

	msg "github.com/Microsoft/hcnproxy/pkg/types"
	"k8s.io/klog/v2"

	"github.com/Azure/aad-pod-identity/pkg/metrics"
	"github.com/Azure/aad-pod-identity/pkg/nmi/server"

	hcnclient "github.com/Microsoft/hcnproxy/pkg/client"

	v1 "github.com/Microsoft/hcsshim"
)

const IMDSEndpoint = "169.254.169.254"

// InitHealthProbe - sets up a health probe which responds with success (200 - OK) once its initialized.
// The contents of the healthz endpoint will be the string "Active" if the condition is satisfied.
// The condition is set to true when the sync cycle has become active in case of MIC and the iptables
// rules set in case of NMI.
func InitHealthProbe(condition *bool) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		if *condition {
			_, _ = w.Write([]byte("Active"))
		} else {
			_, _ = w.Write([]byte("Not Active"))
		}
	})
}

func startAsync(port string) {
	err := http.ListenAndServe(":"+port, nil)
	if err != nil {
		klog.Fatalf("http listen and serve error: %+v", err)
	}

	klog.Info("http listen and serve started !")
}

// Start starts the required http server to start the probe to respond.
func Start(port string) {
	go startAsync(port)
}

// InitAndStart initializes the default probes and starts the http listening port.
func InitAndStart(port string, condition *bool) {
	InitHealthProbe(condition)
	klog.Infof("Initialized health probe on port %s", port)

	// Start the probe.
	Start(port)
	klog.Info("started health probe")
}

// InitAndStartNMIWindowsProbe - Initialize the nmi windows probes and starts the http listening port.
func InitAndStartNMIWindowsProbe(port string, condition *bool, node string, s *server.Server) {
	initNMIWindowsHealthProbe(condition, node, s)
	klog.Infof("Initialized nmi Windows health probe on port %s", port)

	// Start the nmi windows probe.
	Start(port)
	klog.Info("Started NMI Windows health probe")
}

func initNMIWindowsHealthProbe(condition *bool, nodeName string, s *server.Server) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {

		klog.Info("Started to handle healthz: %s", nodeName)

		request := msg.HNSRequest{
			Entity:    msg.EndpointV1,
			Operation: msg.Enumerate,
			Request:   nil,
		}

		statusCode := 200

		klog.Info("Started to call hcn agent.")

		res := hcnclient.InvokeHNSRequest(request)
		if res.Error != nil {
			klog.Info("Call hcn agent failed with error: %+v", res.Error)
			statusCode = 500
		} else {
			klog.Info("Call hcn agent Successfully.")

			b, _ := json.Marshal(res)
			klog.Infof("Server response: %s", string(b))
		}

		klog.Info("Started to compare applied route policies with all existing pods")

		compareAppliedRoutePoliciesWithAllExistingPods(res.Response, s)

		klog.Info("Started to call api server by calling ListAzureIdentitiesFromAPIServer")

		idList, err := s.KubeClient.ListAzureIdentitiesFromAPIServer()
		if err != nil {
			klog.Errorf("health probe call api server by calling ListAzureIdentitiesFromAPIServer failed with error: %+v", err)
			statusCode = 500
		} else {
			klog.Info("Call api server Successfully.")

			var idListNames []string
			for _, idItem := range idList.Items {
				idListNames = append(idListNames, idItem.ObjectMeta.Name)
			}

			klog.Infof("The names of azure identities from API Server response: %v", idListNames)
		}

		w.WriteHeader(statusCode)

		if *condition {
			w.Write([]byte("Active"))
		} else {
			w.Write([]byte("Not Active"))
		}
	})
}

func compareAppliedRoutePoliciesWithAllExistingPods(response []byte, s *server.Server) {
	var endpoints []v1.HNSEndpoint
	err := json.Unmarshal(response, &endpoints)

	if err != nil {
		klog.Errorf("Unmarshal HNS response failed when comparing applied route policies with all existing pods: %+v", err)
		return
	}

	policiesMap := make(map[string][]json.RawMessage)

	for _, ep := range endpoints {
		policiesMap[ep.IPAddress.String()] = ep.Policies
	}

	listPods, err := s.PodClient.ListPods()
	if err != nil {
		klog.Errorf("Failed to list pods when comparing applied route policies with all existing pods: %+v", err)
		return
	}

	for _, podItem := range listPods {
		if podItem.Spec.NodeName == s.NodeName && podItem.Status.PodIP != "" && podItem.Status.PodIP != s.HostIP {
			klog.Infof("Get Host IP, Node Name and Pod IP: \n %s %s %s \n", podItem.Status.HostIP, podItem.Spec.NodeName, podItem.Status.PodIP)

			policies, ok := policiesMap[podItem.Status.PodIP]

			if ok {
				found := false

				for _, policy := range policies {
					if strings.Contains(string(policy), IMDSEndpoint) {
						klog.Infof("Found IMDS endpoint in policies")
						found = true
						break
					}
				}

				if !found {
					s.Reporter.ReportIPRoutePolicyOperation(
						podItem.Status.PodIP, s.NodeName, metrics.NMIHostPolicyMisMatchCountM.M(1))
				}
			} else {
				klog.Errorf("Cannot find pod ip %s in applied route policies", podItem.Status.PodIP)
			}
		}
	}
}
