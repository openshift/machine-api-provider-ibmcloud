/*
Copyright 2021.

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

package machine

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	"github.com/go-openapi/strfmt"
	machinev1 "github.com/openshift/api/machine/v1beta1"
	machinecontroller "github.com/openshift/machine-api-operator/pkg/controller/machine"
	ibmclient "github.com/openshift/machine-api-provider-ibmcloud/pkg/actuators/client"
	mockibm "github.com/openshift/machine-api-provider-ibmcloud/pkg/actuators/client/mock"
	"github.com/openshift/machine-api-provider-ibmcloud/pkg/actuators/util"
	ibmcloudproviderv1 "github.com/openshift/machine-api-provider-ibmcloud/pkg/apis/ibmcloudprovider/v1"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerfake "sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestCreate(t *testing.T) {
	// mock calls
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockIBMClient := mockibm.NewMockClient(mockCtrl)

	cases := []struct {
		testcase          string
		labels            map[string]string
		providerSpec      *ibmcloudproviderv1.IBMCloudMachineProviderSpec
		expectedCondition *ibmcloudproviderv1.IBMCloudMachineProviderCondition
		secret            *corev1.Secret
		expectedError     error
	}{
		{
			testcase: "Create machine succeed ",
			expectedCondition: &ibmcloudproviderv1.IBMCloudMachineProviderCondition{
				Type:    ibmcloudproviderv1.MachineCreated,
				Status:  corev1.ConditionTrue,
				Reason:  machineCreationSucceedReasonCondition,
				Message: machineCreationSucceedMessageCondition,
			},
			providerSpec:  &ibmcloudproviderv1.IBMCloudMachineProviderSpec{},
			expectedError: nil,
		},
		{
			testcase: "Fail on invalid missing machine label",
			labels: map[string]string{
				machinev1.MachineClusterIDLabel: "",
			},
			providerSpec:  &ibmcloudproviderv1.IBMCloudMachineProviderSpec{},
			expectedError: errors.New("failed validating machine provider spec: machine is missing \"machine.openshift.io/cluster-api-cluster\" label"),
		},
		{
			testcase: "Fail on bad user data secret",
			providerSpec: &ibmcloudproviderv1.IBMCloudMachineProviderSpec{
				UserDataSecret: &corev1.LocalObjectReference{
					Name: "invalid_name",
				},
			},
			secret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "invalid_name",
				},
				Data: map[string][]byte{
					"bad_api_key": []byte(""),
				},
			},
			expectedError: errors.New("failed to get user data: secret /invalid_name does not have \"userData\" field set. Thus, no user data applied when creating an instance"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.testcase, func(t *testing.T) {
			providerSpec, err := ibmcloudproviderv1.RawExtensionFromProviderSpec(tc.providerSpec)
			if err != nil {
				t.Fatal(err)
			}

			labels := map[string]string{
				machinev1.MachineClusterIDLabel: "CLUSTERID",
			}
			if tc.labels != nil {
				labels = tc.labels
			}

			// if tc.providerSpec != nil {
			// 	providerSpec = tc.providerSpec
			// }

			machine := &machinev1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
					Labels:    labels,
				},
				Spec: machinev1.MachineSpec{
					ProviderSpec: machinev1.ProviderSpec{
						Value: providerSpec,
					},
				},
			}
			machineScope, err := newMachineScope(machineScopeParams{
				machine: machine,
				client:  controllerfake.NewFakeClient(),
				// providerSpec:   providerSpec,
				// providerStatus: &ibmcloudproviderv1.IBMCloudMachineProviderStatus{},
				ibmClientBuilder: func(coreClient client.Client, secretVal string, providerSpec ibmcloudproviderv1.IBMCloudMachineProviderSpec) (ibmclient.Client, error) {
					return mockIBMClient, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			mockIBMClient.EXPECT().InstanceCreate(gomock.Any(), gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
			mockIBMClient.EXPECT().GetAccountID().Return("accountID", nil).AnyTimes()
			mockIBMClient.EXPECT().InstanceGetByName(gomock.Any(), gomock.Any()).Return(stubInstanceGetByName(machine.Name, &ibmcloudproviderv1.IBMCloudMachineProviderSpec{CredentialsSecret: &corev1.LocalObjectReference{Name: credentialsSecretName}})).AnyTimes()
			mockIBMClient.EXPECT().InstanceDeleteByName(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()
			mockIBMClient.EXPECT().InstanceExistsByName(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()

			reconciler := newReconciler(machineScope)

			if tc.secret != nil {
				reconciler.client = controllerfake.NewClientBuilder().
					WithScheme(scheme.Scheme).
					WithObjects(tc.secret).
					Build()
			}

			err = reconciler.create()

			if tc.expectedCondition != nil {
				if reconciler.providerStatus.Conditions[0].Type != tc.expectedCondition.Type {
					t.Errorf("Expected: %s, got %s", tc.expectedCondition.Type, reconciler.providerStatus.Conditions[0].Type)
				}
				if reconciler.providerStatus.Conditions[0].Status != tc.expectedCondition.Status {
					t.Errorf("Expected: %s, got %s", tc.expectedCondition.Status, reconciler.providerStatus.Conditions[0].Status)
				}
				if reconciler.providerStatus.Conditions[0].Reason != tc.expectedCondition.Reason {
					t.Errorf("Expected: %s, got %s", tc.expectedCondition.Reason, reconciler.providerStatus.Conditions[0].Reason)
				}
				if reconciler.providerStatus.Conditions[0].Message != tc.expectedCondition.Message {
					t.Errorf("Expected: %s, got %s", tc.expectedCondition.Message, reconciler.providerStatus.Conditions[0].Message)
				}
			}

			if tc.expectedError != nil {
				if err == nil {
					t.Error("reconciler was expected to return error")
				}
				if err.Error() != tc.expectedError.Error() {
					t.Errorf("Expected: %v, got %v", tc.expectedError, err)
				}
			} else {
				if err != nil {
					t.Errorf("reconciler was not expected to return error: %v", err)
				}
			}

		})
	}
}

func TestExists(t *testing.T) {
	testCases := []struct {
		name          string
		machine       func() *machinev1.Machine
		ibmClient     func(ctrl *gomock.Controller) ibmclient.Client
		expectedError error
		existsResult  bool
	}{
		{
			name: "Found created instance",
			machine: func() *machinev1.Machine {
				machine, err := stubMachine()
				if err != nil {
					t.Fatalf("unable to build stub machine: %v", err)
				}
				machine.Spec.ProviderSpec = machinev1.ProviderSpec{}
				return machine
			},
			existsResult:  true,
			expectedError: nil,
			ibmClient: func(ctrl *gomock.Controller) ibmclient.Client {
				mockCtrl := gomock.NewController(t)
				mockIBMClient := mockibm.NewMockClient(mockCtrl)
				mockIBMClient.EXPECT().InstanceExistsByName(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
				return mockIBMClient
			},
		},
		{
			name: "Cannot find machine instance",
			machine: func() *machinev1.Machine {
				machine, err := stubMachine()
				if err != nil {
					t.Fatalf("unable to build stub machine: %v", err)
				}
				machine.Spec.ProviderSpec = machinev1.ProviderSpec{}

				return machine
			},
			existsResult:  false,
			expectedError: nil,
			ibmClient: func(ctrl *gomock.Controller) ibmclient.Client {
				mockCtrl := gomock.NewController(t)
				mockIBMClient := mockibm.NewMockClient(mockCtrl)
				mockIBMClient.EXPECT().InstanceExistsByName(gomock.Any(), gomock.Any()).Return(false, nil)
				return mockIBMClient
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)

			machineScope, err := newMachineScope(machineScopeParams{
				machine: tc.machine(),
				client:  controllerfake.NewFakeClient(),
				ibmClientBuilder: func(coreClient client.Client, secretVal string, providerSpec ibmcloudproviderv1.IBMCloudMachineProviderSpec) (ibmclient.Client, error) {
					return tc.ibmClient(mockCtrl), nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			reconciler := newReconciler(machineScope)

			exists, err := reconciler.exists()

			if tc.existsResult != exists {
				t.Errorf("expected reconciler tc.Exists() to return: %v, got %v", tc.existsResult, exists)
			}

			if tc.expectedError != nil {

				if err == nil {
					t.Error("reconciler was expected to return error")
				}

				if err.Error() != tc.expectedError.Error() {
					t.Errorf("expected: %v, got %v", tc.expectedError, err)
				}

			} else {
				if err != nil {
					t.Errorf("reconciler was not expected to return error: %v", err)
				}
			}
		})
	}
}

func machineWithSpec(spec *ibmcloudproviderv1.IBMCloudMachineProviderSpec) *machinev1.Machine {
	providerSpec, err := ibmcloudproviderv1.RawExtensionFromProviderSpec(spec)
	if err != nil {
		panic(err)
	}

	return &machinev1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ibmc-test",
			Namespace: defaultNamespaceName,
		},
		Spec: machinev1.MachineSpec{
			ProviderSpec: machinev1.ProviderSpec{
				Value: providerSpec,
			},
		},
	}
}

func TestGetUserData(t *testing.T) {

	providerSpec := &ibmcloudproviderv1.IBMCloudMachineProviderSpec{
		UserDataSecret: &corev1.LocalObjectReference{
			Name: userDataSecretName,
		},
	}
	testCases := []struct {
		testCase         string
		userDataSecret   *corev1.Secret
		providerSpec     *ibmcloudproviderv1.IBMCloudMachineProviderSpec
		expectedUserdata string
		expectError      bool
	}{
		{
			testCase: "all good",
			userDataSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userDataSecretName,
					Namespace: defaultNamespaceName,
				},
				Data: map[string][]byte{
					userDataSecretKey: []byte("{}"),
				},
			},
			providerSpec:     providerSpec,
			expectedUserdata: "",
			expectError:      false,
		},
		{
			testCase:       "missing secret",
			userDataSecret: nil,
			providerSpec:   providerSpec,
			expectError:    true,
		},
		{
			testCase: "missing key in secret",
			userDataSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      userDataSecretName,
					Namespace: defaultNamespaceName,
				},
				Data: map[string][]byte{
					"userData": []byte("{}"),
				},
			},
			providerSpec: providerSpec,
			expectError:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testCase, func(t *testing.T) {
			clientObjs := []runtime.Object{}

			if tc.userDataSecret != nil {
				clientObjs = append(clientObjs, tc.userDataSecret)
			}

			client := controllerfake.NewFakeClient(clientObjs...)

			// Can't use newMachineScope because it tries to create an API
			// session, and other things unrelated to these tests.
			ms := &machineScope{
				Context:      context.Background(),
				client:       client,
				machine:      machineWithSpec(tc.providerSpec),
				providerSpec: tc.providerSpec,
			}

			userData, err := util.GetCredentialsSecret(ms.client, ms.machine.GetNamespace(), *ms.providerSpec)
			if !tc.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if userData != tc.expectedUserdata {
				t.Errorf("Got: %q, Want: %q", userData, tc.expectedUserdata)
			}
		})
	}
}

func TestReconcileMachineWithCloudState(t *testing.T) {
	// mock calls
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockIBMClient := mockibm.NewMockClient(mockCtrl)

	zone := "test-zone-us-east-1"
	instanceName := "test-Instance-name"
	labels := map[string]string{
		machinev1.MachineClusterIDLabel: "CLUSTERID",
	}

	providerSpec, err := ibmcloudproviderv1.RawExtensionFromProviderSpec(&ibmcloudproviderv1.IBMCloudMachineProviderSpec{
		Zone: zone,
	})
	if err != nil {
		t.Fatal(err)
	}
	machine := &machinev1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      instanceName,
			Namespace: "",
			Labels:    labels,
		},
		Spec: machinev1.MachineSpec{
			ProviderSpec: machinev1.ProviderSpec{
				Value: providerSpec,
			},
		},
	}
	machineScope, err := newMachineScope(machineScopeParams{
		machine: machine,
		client:  controllerfake.NewFakeClient(),
		// providerSpec:   providerSpec,
		// providerStatus: &ibmcloudproviderv1.IBMCloudMachineProviderStatus{},
		ibmClientBuilder: func(coreClient client.Client, secretVal string, providerSpec ibmcloudproviderv1.IBMCloudMachineProviderSpec) (ibmclient.Client, error) {
			return mockIBMClient, nil
		},
	})

	// account ID returned from stubGetAccountID
	accountID := "01234_5678_90ab_cdef"
	mockIBMClient.EXPECT().GetAccountID().Return(accountID, nil).AnyTimes()
	// instance ID returned from stubInstanceGetByName
	instanceID := "0727_xyz-xyz-cccc-aaba-cacdaccad"
	mockIBMClient.EXPECT().InstanceGetByName(gomock.Any(), gomock.Any()).Return(stubInstanceGetByName(machine.Name, &ibmcloudproviderv1.IBMCloudMachineProviderSpec{CredentialsSecret: &corev1.LocalObjectReference{Name: credentialsSecretName}})).AnyTimes()

	expectedNodeAddresses := []corev1.NodeAddress{
		{
			Type:    "InternalDNS",
			Address: instanceName,
		},
		{
			Type:    "InternalIP",
			Address: "10.0.0.1",
		},
	}
	expectedProviderID := fmt.Sprintf("ibm://%s///CLUSTERID/%s", accountID, instanceID)

	r := newReconciler(machineScope)
	if err := r.reconcileMachineWithCloudState(nil); err != nil {
		t.Errorf("reconciler was not expected to return error: %v", err)
	}

	if r.machine.Status.Addresses[0] != expectedNodeAddresses[0] {
		t.Errorf("Expected: %s, got: %s", expectedNodeAddresses[0], r.machine.Status.Addresses[0])
	}
	if r.machine.Status.Addresses[1] != expectedNodeAddresses[1] {
		t.Errorf("Expected: %s, got: %s", expectedNodeAddresses[1], r.machine.Status.Addresses[1])
	}

	if *r.machine.Spec.ProviderID != expectedProviderID {
		t.Errorf("Expected: %s, got: %s", expectedProviderID, *r.machine.Spec.ProviderID)
	}
	if *r.providerStatus.InstanceState != "running" {
		t.Errorf("Expected: %s, got: %s", "running", *r.providerStatus.InstanceState)
	}
	if *r.providerStatus.InstanceID != instanceID {
		t.Errorf("Expected: %s, got: %s", instanceID, *r.providerStatus.InstanceID)
	}
}

// Statuses, lifecycle states and lifecycle reasons of an instance, used by the tests of the lifecycle state checks.
// These are the values the IBM Cloud API reports, so they are deliberately not the constants of the provider.
const (
	statusDeleting               = "deleting"
	lifecycleStateStable         = "stable"
	lifecycleStateFailed         = "failed"
	lifecycleStatePending        = "pending"
	lifecycleReasonCode          = "pending_registration"
	lifecycleReasonMessage       = "The registration for the instance is in progress."
	lifecycleReasonFailedCode    = "failed_registration"
	lifecycleReasonFailedMessage = "The registration for the instance has failed."
)

func TestReconcileMachineWithCloudStateLifecycleState(t *testing.T) {
	pastLifecycleDeadline := (machineLifecycleStableDeadlineMinutes + 1) * time.Minute

	cases := []struct {
		name           string
		phase          string
		status         string
		lifecycleState string
		createdAgo     time.Duration
		expectRequeue  bool
		expectFailed   bool
	}{
		{
			name:           "Instance with stable lifecycle state is provisioned",
			phase:          machinev1.PhaseProvisioning,
			lifecycleState: lifecycleStateStable,
			createdAgo:     time.Minute,
			expectRequeue:  false,
			expectFailed:   false,
		},
		{
			name:           "Instance with pending lifecycle state within deadline is requeued",
			phase:          machinev1.PhaseProvisioning,
			lifecycleState: lifecycleStatePending,
			createdAgo:     time.Minute,
			expectRequeue:  true,
			expectFailed:   false,
		},
		{
			name:           "Machine without phase with pending lifecycle state within deadline is requeued",
			lifecycleState: lifecycleStatePending,
			createdAgo:     time.Minute,
			expectRequeue:  true,
			expectFailed:   false,
		},
		{
			name:           "Machine with pending lifecycle state past deadline fails",
			phase:          machinev1.PhaseProvisioning,
			lifecycleState: lifecycleStatePending,
			createdAgo:     pastLifecycleDeadline,
			expectRequeue:  false,
			expectFailed:   true,
		},
		{
			name:           "Machine with failed lifecycle state fails within deadline",
			phase:          machinev1.PhaseProvisioning,
			lifecycleState: lifecycleStateFailed,
			createdAgo:     time.Minute,
			expectRequeue:  false,
			expectFailed:   true,
		},
		{
			name:           "Machine whose instance is being deleted does not fail",
			phase:          machinev1.PhaseProvisioning,
			status:         statusDeleting,
			lifecycleState: lifecycleStatePending,
			createdAgo:     pastLifecycleDeadline,
			expectRequeue:  true,
			expectFailed:   false,
		},
		{
			name:           "Provisioned machine with pending lifecycle state past deadline does not fail",
			phase:          machinev1.PhaseProvisioned,
			lifecycleState: lifecycleStatePending,
			createdAgo:     pastLifecycleDeadline,
			expectRequeue:  false,
			expectFailed:   false,
		},
		{
			name:           "Running machine with pending lifecycle state past deadline does not fail",
			phase:          machinev1.PhaseRunning,
			lifecycleState: lifecycleStatePending,
			createdAgo:     pastLifecycleDeadline,
			expectRequeue:  false,
			expectFailed:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mockCtrl := gomock.NewController(t)
			mockIBMClient := mockibm.NewMockClient(mockCtrl)

			providerSpec, err := ibmcloudproviderv1.RawExtensionFromProviderSpec(&ibmcloudproviderv1.IBMCloudMachineProviderSpec{})
			if err != nil {
				t.Fatal(err)
			}

			machine := &machinev1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-instance-name",
					Namespace: "test-ns",
					Labels:    map[string]string{machinev1.MachineClusterIDLabel: "CLUSTERID"},
				},
				Spec: machinev1.MachineSpec{
					ProviderSpec: machinev1.ProviderSpec{
						Value: providerSpec,
					},
				},
			}
			if tc.phase != "" {
				machine.Status.Phase = &tc.phase
			}

			machineScope, err := newMachineScope(machineScopeParams{
				machine: machine,
				client:  controllerfake.NewFakeClient(),
				ibmClientBuilder: func(coreClient client.Client, secretVal string, providerSpec ibmcloudproviderv1.IBMCloudMachineProviderSpec) (ibmclient.Client, error) {
					return mockIBMClient, nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			instance, err := stubInstanceGetByName(machine.Name, nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.status != "" {
				instance.Status = &tc.status
			}
			instance.LifecycleState = &tc.lifecycleState
			instance.LifecycleReasons = []vpcv1.InstanceLifecycleReason{{
				Code:    ptr.To(lifecycleReasonCode),
				Message: ptr.To(lifecycleReasonMessage),
			}}
			createdAt := strfmt.DateTime(time.Now().Add(-tc.createdAgo))
			instance.CreatedAt = &createdAt

			mockIBMClient.EXPECT().GetAccountID().Return("accountID", nil).AnyTimes()
			mockIBMClient.EXPECT().InstanceGetByName(gomock.Any(), gomock.Any()).Return(instance, nil).AnyTimes()

			r := newReconciler(machineScope)
			err = r.reconcileMachineWithCloudState(nil)

			var requeueErr *machinecontroller.RequeueAfterError
			if tc.expectRequeue != errors.As(err, &requeueErr) {
				t.Errorf("Expected requeue to be %v, got error: %v", tc.expectRequeue, err)
			}

			phase := ptr.Deref(r.machine.Status.Phase, "")
			if tc.expectFailed {
				if phase != machinev1.PhaseFailed {
					t.Errorf("Expected machine phase %s, got: %s", machinev1.PhaseFailed, phase)
				}
				if ptr.Deref(r.machine.Status.ErrorReason, "") != machinev1.CreateMachineError {
					t.Errorf("Expected error reason %s, got: %v", machinev1.CreateMachineError, r.machine.Status.ErrorReason)
				}
				if ptr.Deref(r.machine.Status.ErrorMessage, "") == "" {
					t.Error("Expected an error message")
				}
				var machineErr *machinecontroller.MachineError
				if !errors.As(err, &machineErr) {
					t.Errorf("Expected a MachineError, got: %v", err)
				}
			} else {
				if phase == machinev1.PhaseFailed {
					t.Error("Expected machine not to be failed")
				}
				if r.machine.Status.ErrorMessage != nil {
					t.Errorf("Expected no error message, got: %s", *r.machine.Status.ErrorMessage)
				}
			}
		})
	}
}

func TestProvisioningFailureMessage(t *testing.T) {
	pastLifecycleDeadline := (machineLifecycleStableDeadlineMinutes + 1) * time.Minute

	cases := []struct {
		name            string
		phase           string
		status          string
		lifecycleState  string
		createdAgo      time.Duration
		expectedMessage string
	}{
		{
			name:            "Instance with stable lifecycle state",
			phase:           machinev1.PhaseProvisioning,
			lifecycleState:  lifecycleStateStable,
			createdAgo:      pastLifecycleDeadline,
			expectedMessage: "",
		},
		{
			name:            "Instance with pending lifecycle state within deadline",
			phase:           machinev1.PhaseProvisioning,
			lifecycleState:  lifecycleStatePending,
			createdAgo:      time.Minute,
			expectedMessage: "",
		},
		{
			name:            "Instance with pending lifecycle state past deadline",
			phase:           machinev1.PhaseProvisioning,
			lifecycleState:  lifecycleStatePending,
			createdAgo:      pastLifecycleDeadline,
			expectedMessage: `instance lifecycle state is "pending", expected "stable" within 15 minutes of the instance creation: pending_registration: The registration for the instance is in progress.`,
		},
		{
			name:            "Instance with failed lifecycle state within deadline",
			phase:           machinev1.PhaseProvisioning,
			lifecycleState:  lifecycleStateFailed,
			createdAgo:      time.Minute,
			expectedMessage: `instance lifecycle state is "failed": pending_registration: The registration for the instance is in progress.`,
		},
		{
			name:            "Instance that is being deleted",
			phase:           machinev1.PhaseProvisioning,
			status:          statusDeleting,
			lifecycleState:  lifecycleStatePending,
			createdAgo:      pastLifecycleDeadline,
			expectedMessage: "",
		},
		{
			name:            "Machine without a phase",
			lifecycleState:  lifecycleStatePending,
			createdAgo:      pastLifecycleDeadline,
			expectedMessage: `instance lifecycle state is "pending", expected "stable" within 15 minutes of the instance creation: pending_registration: The registration for the instance is in progress.`,
		},
		{
			name:            "Provisioned machine",
			phase:           machinev1.PhaseProvisioned,
			lifecycleState:  lifecycleStatePending,
			createdAgo:      pastLifecycleDeadline,
			expectedMessage: "",
		},
		{
			name:            "Running machine",
			phase:           machinev1.PhaseRunning,
			lifecycleState:  lifecycleStatePending,
			createdAgo:      pastLifecycleDeadline,
			expectedMessage: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			machine := &machinev1.Machine{ObjectMeta: metav1.ObjectMeta{Name: "test-instance-name"}}
			if tc.phase != "" {
				machine.Status.Phase = &tc.phase
			}
			r := Reconciler{machineScope: &machineScope{machine: machine}}

			createdAt := strfmt.DateTime(time.Now().Add(-tc.createdAgo))
			instance := &vpcv1.Instance{
				LifecycleState: &tc.lifecycleState,
				CreatedAt:      &createdAt,
				LifecycleReasons: []vpcv1.InstanceLifecycleReason{{
					Code:    ptr.To(lifecycleReasonCode),
					Message: ptr.To(lifecycleReasonMessage),
				}},
			}
			if tc.status != "" {
				instance.Status = &tc.status
			}

			if message := r.provisioningFailureMessage(instance); message != tc.expectedMessage {
				t.Errorf("Expected: %q, got: %q", tc.expectedMessage, message)
			}
		})
	}
}

func TestProvisioningFailureMessageWithoutCreationTime(t *testing.T) {
	phase := machinev1.PhaseProvisioning
	machine := &machinev1.Machine{
		ObjectMeta: metav1.ObjectMeta{Name: "test-instance-name"},
		Status:     machinev1.MachineStatus{Phase: &phase},
	}
	r := Reconciler{machineScope: &machineScope{machine: machine}}

	instance := &vpcv1.Instance{LifecycleState: ptr.To(lifecycleStatePending)}
	if message := r.provisioningFailureMessage(instance); message != "" {
		t.Errorf("Expected no message, got: %q", message)
	}
}

func TestLifecycleReasons(t *testing.T) {
	cases := []struct {
		name     string
		reasons  []vpcv1.InstanceLifecycleReason
		expected string
	}{
		{
			name:     "No reasons",
			expected: "",
		},
		{
			name:     "Reason without a code and a message",
			reasons:  []vpcv1.InstanceLifecycleReason{{}},
			expected: "",
		},
		{
			name:     "Reason without a message",
			reasons:  []vpcv1.InstanceLifecycleReason{{Code: ptr.To("internal_error")}},
			expected: ": internal_error",
		},
		{
			name:     "Reason without a code",
			reasons:  []vpcv1.InstanceLifecycleReason{{Message: ptr.To("Internal error")}},
			expected: ": Internal error",
		},
		{
			name:     "Reason with a code and a message",
			reasons:  []vpcv1.InstanceLifecycleReason{{Code: ptr.To(lifecycleReasonCode), Message: ptr.To(lifecycleReasonMessage)}},
			expected: fmt.Sprintf(": %s: %s", lifecycleReasonCode, lifecycleReasonMessage),
		},
		{
			name: "Multiple reasons",
			reasons: []vpcv1.InstanceLifecycleReason{
				{Code: ptr.To("pending_registration"), Message: ptr.To("Registration in progress.")},
				{Code: ptr.To("internal_error")},
				{},
			},
			expected: ": pending_registration: Registration in progress., internal_error",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reasons := lifecycleReasons(&vpcv1.Instance{LifecycleReasons: tc.reasons}); reasons != tc.expected {
				t.Errorf("Expected: %q, got: %q", tc.expected, reasons)
			}
		})
	}
}

func TestFailedMachineIsPersisted(t *testing.T) {
	mockCtrl := gomock.NewController(t)
	mockIBMClient := mockibm.NewMockClient(mockCtrl)

	providerSpec, err := ibmcloudproviderv1.RawExtensionFromProviderSpec(&ibmcloudproviderv1.IBMCloudMachineProviderSpec{})
	if err != nil {
		t.Fatal(err)
	}
	phase := machinev1.PhaseProvisioning
	machine := &machinev1.Machine{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-instance-name",
			Namespace: "test-ns",
			Labels:    map[string]string{machinev1.MachineClusterIDLabel: "CLUSTERID"},
		},
		Spec: machinev1.MachineSpec{
			ProviderSpec: machinev1.ProviderSpec{Value: providerSpec},
		},
		Status: machinev1.MachineStatus{Phase: &phase},
	}

	fakeClient := controllerfake.NewClientBuilder().
		WithScheme(scheme.Scheme).
		WithObjects(machine).
		WithStatusSubresource(&machinev1.Machine{}).
		Build()
	machineScope, err := newMachineScope(machineScopeParams{
		machine: machine,
		client:  fakeClient,
		ibmClientBuilder: func(coreClient client.Client, secretVal string, providerSpec ibmcloudproviderv1.IBMCloudMachineProviderSpec) (ibmclient.Client, error) {
			return mockIBMClient, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	instance, err := stubInstanceGetByName(machine.Name, nil)
	if err != nil {
		t.Fatal(err)
	}
	instance.LifecycleState = ptr.To(lifecycleStateFailed)
	instance.LifecycleReasons = []vpcv1.InstanceLifecycleReason{{
		Code:    ptr.To(lifecycleReasonFailedCode),
		Message: ptr.To(lifecycleReasonFailedMessage),
	}}
	mockIBMClient.EXPECT().GetAccountID().Return("accountID", nil).AnyTimes()
	mockIBMClient.EXPECT().InstanceGetByName(gomock.Any(), gomock.Any()).Return(instance, nil).AnyTimes()

	// The machine is persisted by the scope, like the actuator does when the reconciler returns an error
	if err := newReconciler(machineScope).update(); err == nil {
		t.Error("reconciler was expected to return an error")
	}
	if err := machineScope.Close(); err != nil {
		t.Fatalf("failed to close machine scope: %v", err)
	}

	persisted := &machinev1.Machine{}
	if err := fakeClient.Get(context.Background(), client.ObjectKeyFromObject(machine), persisted); err != nil {
		t.Fatalf("failed to get machine: %v", err)
	}
	if persistedPhase := ptr.Deref(persisted.Status.Phase, ""); persistedPhase != machinev1.PhaseFailed {
		t.Errorf("Expected persisted phase %s, got: %s", machinev1.PhaseFailed, persistedPhase)
	}
	if ptr.Deref(persisted.Status.ErrorReason, "") != machinev1.CreateMachineError {
		t.Errorf("Expected persisted error reason %s, got: %v", machinev1.CreateMachineError, persisted.Status.ErrorReason)
	}
	expectedErrorMessage := `instance lifecycle state is "failed": failed_registration: The registration for the instance has failed.`
	if errorMessage := ptr.Deref(persisted.Status.ErrorMessage, ""); errorMessage != expectedErrorMessage {
		t.Errorf("Expected persisted error message: %q, got: %q", expectedErrorMessage, errorMessage)
	}
}

func TestSetMachineCloudProviderSpecifics(t *testing.T) {
	dummyStatus := "testStatus"
	dummyProfile := "testProfile"
	dummyZone := "testZone"
	dummyRegion := "testRegion"

	r := Reconciler{
		machineScope: &machineScope{
			machine: &machinev1.Machine{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "",
					Namespace: "",
				},
			},
			providerSpec: &ibmcloudproviderv1.IBMCloudMachineProviderSpec{
				Profile: dummyProfile,
				Region:  dummyRegion,
				Zone:    dummyZone,
			},
		},
	}

	instance := &vpcv1.Instance{
		Status: &dummyStatus,
	}

	r.setMachineCloudProviderSpecifics(instance)

	actualInstanceStateAnnotation := r.machine.Annotations[machinecontroller.MachineInstanceStateAnnotationName]
	if actualInstanceStateAnnotation != *instance.Status {
		t.Errorf("Expected instance state annotation: %v, got: %v", actualInstanceStateAnnotation, *instance.Status)
	}

	actualMachineProfileLabel := r.machine.Labels[machinecontroller.MachineInstanceTypeLabelName]
	if actualMachineProfileLabel != r.providerSpec.Profile {
		t.Errorf("Expected machine type label: %v, got: %v", actualMachineProfileLabel, r.providerSpec.Profile)
	}

	actualMachineRegionLabel := r.machine.Labels[machinecontroller.MachineRegionLabelName]
	if actualMachineRegionLabel != r.providerSpec.Region {
		t.Errorf("Expected machine region label: %v, got: %v", actualMachineRegionLabel, r.providerSpec.Region)
	}

	actualMachineAZLabel := r.machine.Labels[machinecontroller.MachineAZLabelName]
	if actualMachineAZLabel != r.providerSpec.Zone {
		t.Errorf("Expected machine zone label: %v, got: %v", actualMachineAZLabel, r.providerSpec.Zone)
	}
}

func TestDelete(t *testing.T) {
	// mock calls
	mockCtrl := gomock.NewController(t)
	defer mockCtrl.Finish()
	mockIBMClient := mockibm.NewMockClient(mockCtrl)

	machineScope := machineScope{
		machine: &machinev1.Machine{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "",
				Namespace: "",
				Labels: map[string]string{
					machinev1.MachineClusterIDLabel: "CLUSTERID",
				},
			},
		},
		client:         controllerfake.NewFakeClient(),
		providerSpec:   &ibmcloudproviderv1.IBMCloudMachineProviderSpec{},
		providerStatus: &ibmcloudproviderv1.IBMCloudMachineProviderStatus{},
		ibmClient:      mockIBMClient,
	}

	reconciler := newReconciler(&machineScope)

	mockIBMClient.EXPECT().InstanceExistsByName(gomock.Any(), gomock.Any()).Return(true, nil).AnyTimes()
	mockIBMClient.EXPECT().InstanceDeleteByName(gomock.Any(), gomock.Any()).Return(nil).AnyTimes()

	if err := reconciler.delete(); err != nil {
		if _, ok := err.(*machinecontroller.RequeueAfterError); !ok {
			t.Errorf("reconciler was not expected to return error: %v", err)
		}
	}
}
