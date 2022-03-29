//go:build windows
// +build windows

package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	client "github.com/Microsoft/hcnproxy/pkg/client"
	msg "github.com/Microsoft/hcnproxy/pkg/types"
)

type mockinvokeHNSRequest func(req msg.HNSRequest) *msg.HNSResponse

const (
	podIp1 = "127.10.0.152"
	podIp2 = "127.10.0.153"
)

func mockGoodInvokeHNSRequest(req msg.HNSRequest) *msg.HNSResponse {
	data := []byte(`[{"id": "testid", "IPAddress": "127.10.0.153"}]`)
	raw := json.RawMessage(data)
	return &msg.HNSResponse{
		Error:    nil,
		Response: raw,
	}
}

func mockFailGetEndpointInvokeHNSRequest(req msg.HNSRequest) *msg.HNSResponse {
	data := []byte(`[{"id": "testid", "IPAddress": "127.10.0.152"}]`)
	raw := json.RawMessage(data)

	if req.Operation == msg.Enumerate {
		return &msg.HNSResponse{
			Error:    errors.New("Failed to get endpoint by ip"),
			Response: raw,
		}
	}

	return &msg.HNSResponse{
		Error:    nil,
		Response: raw,
	}
}

func mockFailApplyPolicyInvokeHNSRequest(req msg.HNSRequest) *msg.HNSResponse {
	data := []byte(`[{"id": "testid", "IPAddress": "127.10.0.152"}]`)
	raw := json.RawMessage(data)

	if req.Operation == msg.Enumerate {
		return &msg.HNSResponse{
			Error:    nil,
			Response: raw,
		}
	} else if req.Operation == msg.Modify {
		return &msg.HNSResponse{
			Error:    errors.New("Failed to apply policy"),
			Response: raw,
		}
	}

	return &msg.HNSResponse{}
}

func TestApplyEndpointRoutePolicy(t *testing.T) {

	cases := []struct {
		name              string
		podIP             string
		metadataIP        string
		metadataPort      string
		nmiIP             string
		nmiPort           string
		expectedError     error
		expectedErrorType string
		mockFunc          mockinvokeHNSRequest
	}{
		{
			name:              "SuccessApplyPolicy",
			podIP:             podIp2,
			metadataIP:        "169.254.169.254",
			metadataPort:      "80",
			nmiIP:             "127.10.0.23",
			nmiPort:           "8329",
			expectedError:     nil,
			expectedErrorType: "",
			mockFunc:          mockGoodInvokeHNSRequest,
		},
		{
			name:              "Fail with missing Pod IP",
			podIP:             "",
			metadataIP:        "169.254.169.254",
			metadataPort:      "80",
			nmiIP:             "127.10.0.23",
			nmiPort:           "8329",
			expectedError:     errors.New("Missing IP Address"),
			expectedErrorType: "NotFound",
			mockFunc:          client.InvokeHNSRequest,
		},
		{
			name:              "Failed getEndpointByIP",
			podIP:             podIp1,
			metadataIP:        "169.254.169.254",
			metadataPort:      "80",
			nmiIP:             "127.10.0.23",
			nmiPort:           "8329",
			expectedError:     fmt.Errorf("Get endpoint for Pod IP - %s. Error: Failed to get endpoint by ip", podIp1),
			expectedErrorType: "InvalidOperation",
			mockFunc:          mockFailGetEndpointInvokeHNSRequest,
		},
		{
			name:              "Failed addEndpointPolicy",
			podIP:             podIp1,
			metadataIP:        "169.254.169.254",
			metadataPort:      "80",
			nmiIP:             "127.10.0.23",
			nmiPort:           "8329",
			expectedError:     fmt.Errorf("Could not add policy for ip [%s] to endpoint - testid. Error: Failed to apply policy", podIp1),
			expectedErrorType: "UnKnown",
			mockFunc:          mockFailApplyPolicyInvokeHNSRequest,
		},
	}

	for i, tc := range cases {
		InvokeHNSRequestFunc = tc.mockFunc
		t.Log(i, tc.name)
		err, et := ApplyEndpointRoutePolicy(tc.podIP, tc.metadataIP, tc.metadataPort, tc.nmiIP, tc.nmiPort)

		if err != nil {
			t.Log(i, err.Error(), et)

			if tc.expectedError == nil {
				t.Fatalf("no error expected, but found - %s", err)
			} else if tc.expectedError.Error() != err.Error() {
				t.Fatalf("expected error to be - %s, but found - %s", tc.expectedError, err)
			} else if tc.expectedErrorType != et {
				t.Fatalf("expected error type to be - %s, but found - %s", tc.expectedErrorType, et)
			}
		}
	}

	InvokeHNSRequestFunc = client.InvokeHNSRequest
}

func TestDeleteEndpointRoutePolicy(t *testing.T) {
	cases := []struct {
		name              string
		podIP             string
		metadataIP        string
		metadataPort      string
		nmiIP             string
		nmiPort           string
		expectedError     error
		expectedErrorType string
		mockFunc          mockinvokeHNSRequest
	}{
		{
			name:              "Failed addEndpointPolicy",
			podIP:             podIp1,
			metadataIP:        "169.254.169.254",
			metadataPort:      "80",
			nmiIP:             "127.10.0.23",
			nmiPort:           "8329",
			expectedError:     fmt.Errorf("Could't delete policy for ip [%s] to endpoint - testid. Error: Failed to apply policy", podIp1),
			expectedErrorType: "UnKnown",
			mockFunc:          mockFailApplyPolicyInvokeHNSRequest,
		},
	}

	for i, tc := range cases {
		InvokeHNSRequestFunc = tc.mockFunc
		t.Log(i, tc.name)
		err, _ := DeleteEndpointRoutePolicy(tc.podIP, tc.metadataIP)

		if err != nil {
			if tc.expectedError == nil {
				t.Fatalf("no error expected, but found - %s", err)
			} else if tc.expectedError.Error() != err.Error() {
				t.Fatalf("expected error to be - %s, but found - %s", tc.expectedError, err)
			}
		}
	}
	InvokeHNSRequestFunc = client.InvokeHNSRequest
}
