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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/IBM/vpc-go-sdk/vpcv1"
	igntypes "github.com/coreos/ignition/v2/config/v3_2/types"
	machinev1 "github.com/openshift/api/machine/v1beta1"
	machinecontroller "github.com/openshift/machine-api-operator/pkg/controller/machine"
	"github.com/openshift/machine-api-operator/pkg/metrics"
	apicorev1 "k8s.io/api/core/v1"
	apimachineryerrors "k8s.io/apimachinery/pkg/api/errors"
	klog "k8s.io/klog/v2"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	ibmcloudclienterrors "github.com/openshift/machine-api-provider-ibmcloud/pkg/actuators/client/errors"
	ibmcloudproviderv1 "github.com/openshift/machine-api-provider-ibmcloud/pkg/apis/ibmcloudprovider/v1"
)

const (
	requeueAfterSeconds      = 20
	requeueAfterFatalSeconds = 180
	userDataSecretKey        = "userData"

	// The following values are used for machine replacement, when it appears the machine is stuck and unresponsive as part of
	// https://issues.redhat.com/browse/OCPBUGS-1327
	// Time in minutes a Provisioned machine has before a delete is called to force re-create
	machineReplaceDeadlineMinutes = 15
	machineDeleteDeadlineMinutes  = 10
	// Status of IBM Cloud instances
	ibmStatusRunning  = "running"
	ibmStatusDeleting = "deleting"
	// Used to check Ignition Config sources for Https locations only (for MCS)
	httpsPrefix = "https://"
)

// Reconciler are list of services required by machine actuator, easy to create a fake
type Reconciler struct {
	*machineScope
}

// NewReconciler populates all the services based on input scope
func newReconciler(scope *machineScope) *Reconciler {
	return &Reconciler{
		scope,
	}
}

// Create creates an instance via machine cr which is handled by cluster-api
func (r *Reconciler) create() error {

	if err := validateMachine(*r.machine); err != nil {
		return machinecontroller.InvalidMachineConfiguration("failed validating machine provider spec: %v", err)
	}

	userData, err := r.getUserData()
	if err != nil {
		return fmt.Errorf("failed to get user data: %w", err)
	}

	// Create an instance
	_, err = r.ibmClient.InstanceCreate(r.machine.Name, r.providerSpec, userData)

	if err != nil {
		klog.Errorf("%s: error occured while creating machine: %v", r.machine.Name, err)
		metrics.RegisterFailedInstanceCreate(&metrics.MachineLabels{
			Name:      r.machine.Name,
			Namespace: r.machine.Namespace,
			Reason:    err.Error(),
		})

		if reconcileMachineWithCloudStateErr := r.reconcileMachineWithCloudState(&ibmcloudproviderv1.IBMCloudMachineProviderCondition{
			Type:    ibmcloudproviderv1.MachineCreated,
			Status:  apicorev1.ConditionFalse,
			Reason:  ibmcloudproviderv1.MachineCreationFailed,
			Message: err.Error(),
		}); reconcileMachineWithCloudStateErr != nil {
			klog.Errorf("failed to reconcile machine condtion with cloud state: %v", reconcileMachineWithCloudStateErr)
		}
		return fmt.Errorf("failed to create instance via ibm vpc client: %w", err)
	}

	// Update Machine Spec and status with instance info
	return r.reconcileMachineWithCloudState(nil)
}

// update gets instance details and reconciles the machine resource with its state
func (r *Reconciler) update() error {
	if err := validateMachine(*r.machine); err != nil {
		return machinecontroller.InvalidMachineConfiguration("failed validating machine provider spec: %v", err)
	}

	// Update cloud state
	return r.reconcileMachineWithCloudState(nil)
}

func validateMachine(machine machinev1.Machine) error {
	if machine.Labels[machinev1.MachineClusterIDLabel] == "" {
		return machinecontroller.InvalidMachineConfiguration("machine is missing %q label", machinev1.MachineClusterIDLabel)
	}

	return nil
}

// Returns true if machine exists.
func (r *Reconciler) exists() (bool, error) {
	// check if instance exist
	exist, err := r.ibmClient.InstanceExistsByName(r.machine.GetName(), r.providerSpec)
	return exist, err
}

// delete makes a request to delete an instance
func (r *Reconciler) delete() error {

	// Check if the instance exists
	exists, err := r.exists()
	if err != nil {
		return err
	}

	// Found the instance?
	if !exists {
		klog.Infof("%s: Machine not found during delete, skipping", r.machine.Name)
		return nil
	}

	// Delete the instance
	if err = r.ibmClient.InstanceDeleteByName(r.machine.GetName(), r.providerSpec); err != nil {
		metrics.RegisterFailedInstanceDelete(&metrics.MachineLabels{
			Name:      r.machine.Name,
			Namespace: r.machine.Namespace,
			Reason:    err.Error(),
		})
		return fmt.Errorf("failed to delete instance via ibmClient: %v", err)
	}

	klog.Infof("%s: machine status is exists, requeuing...", r.machine.Name)

	return &machinecontroller.RequeueAfterError{RequeueAfter: requeueAfterSeconds * time.Second}
}

// getUserData returns User data ignition config
func (r *Reconciler) getUserData() (string, error) {
	if r.providerSpec == nil || r.providerSpec.UserDataSecret == nil {
		return "", nil
	}

	var userDataSecret apicorev1.Secret

	if err := r.client.Get(context.Background(), client.ObjectKey{Namespace: r.machine.GetNamespace(), Name: r.providerSpec.UserDataSecret.Name}, &userDataSecret); err != nil {
		if apimachineryerrors.IsNotFound(err) {
			return "", machinecontroller.InvalidMachineConfiguration("user data secret %q in namespace %q not found: %v", r.providerSpec.UserDataSecret.Name, r.machine.GetNamespace(), err)
		}
		return "", fmt.Errorf("error getting user data secret %q in namespace %q: %v", r.providerSpec.UserDataSecret.Name, r.machine.GetNamespace(), err)
	}
	data, exists := userDataSecret.Data[userDataSecretKey]
	if !exists {
		return "", machinecontroller.InvalidMachineConfiguration("secret %v/%v does not have %q field set. Thus, no user data applied when creating an instance", r.machine.GetNamespace(), r.providerSpec.UserDataSecret.Name, userDataSecretKey)
	}
	return string(data), nil
}

// reconcileMachineWithCloudState reconcile Machine status and spec with the lastest cloud state
func (r *Reconciler) reconcileMachineWithCloudState(conditionFailed *ibmcloudproviderv1.IBMCloudMachineProviderCondition) error {
	// Update providerStatus.Conditions with the failed condtions
	if conditionFailed != nil {
		r.providerStatus.Conditions = reconcileProviderConditions(r.providerStatus.Conditions, *conditionFailed)
		return nil
	}

	// conditionFailed is nil, get the cloud instance and reconcile the fields
	newInstance, err := r.ibmClient.InstanceGetByName(r.machine.Name, r.providerSpec)
	if err != nil {
		// Check whether the machine was recently removed to replace a stuck machine in order to resolve
		// https://issues.redhat.com/browse/OCPBUGS-1327
		// We need to wait until the IBM Cloud VSI is actually gone before re-creating it with the same name (to prevent cascading issues using a different name)
		// Check if the machine just completed deletion and should now have a replacement in progress
		if _, okay := err.(*ibmcloudclienterrors.InstanceNotFoundError); okay && conditionTypeCheck(r.providerStatus.Conditions, ibmcloudproviderv1.MachineReplacement) != nil {
			// Verify the instance no longer exists, using the instance Id, return an error if instance with same Id but different name exists (in case it was renamed)
			if invalidInstance, err := r.ibmClient.InstanceGetByID(*r.providerStatus.InstanceID); err == nil {
				klog.Warningf("%s: machine name and instance Id mismatch during replacement delete check", r.machine.Name)
				return fmt.Errorf("machine %s name for replaced machine doesn't match expected %s for instance id: %s", *invalidInstance.Name, r.machine.Name, *r.providerStatus.InstanceID)
			}
			klog.Infof("%s: setting machine's status to Provisioning for replacement machine", r.machine.Name)
			r.machine.Status.Phase = ptr.To(machinev1.PhaseProvisioning)
			return nil
		}
		return fmt.Errorf("get instance failed with an error: %q", err)
	}

	// Check whether the machine is being deleted due to a replacement request and then determine if that deletion has passed a deadline, 'machineDeletedDeadline'
	if newInstance.Status != nil && *newInstance.Status == ibmStatusDeleting {
		if machineReplacementCondition := conditionTypeCheck(r.providerStatus.Conditions, ibmcloudproviderv1.MachineReplacement); machineReplacementCondition != nil {
			// Update machine replacement status to in progress if it hasn't been yet
			if machineReplacementCondition.Reason == ibmcloudproviderv1.MachineReplacementRequested {
				klog.Infof("%s: machine replacement now in progress", r.machine.Name)
				r.providerStatus.Conditions = reconcileProviderConditions(r.providerStatus.Conditions, ibmcloudproviderv1.IBMCloudMachineProviderCondition{
					Type:    ibmcloudproviderv1.MachineReplacement,
					Reason:  ibmcloudproviderv1.MachineReplacementInProgress,
					Message: machineReplacementInProgressMessageCondition,
					Status:  apicorev1.ConditionTrue,
				})
				return nil
			} else if machineReplacementCondition.Reason == ibmcloudproviderv1.MachineReplacementFailed {
				// If replacement failed, attempt to update the status to Failed, if not already done
				klog.Infof("%s: machine replacement failed", r.machine.Name)
				if r.machine.Status.Phase != nil && *r.machine.Status.Phase != machinev1.PhaseFailed {
					r.machine.Status.Phase = ptr.To(machinev1.PhaseFailed)
					return nil
				}
			}
			// Machine replacement should be in progress
			// Check whether the machine is past the deletion deadline, returning an error if so
			klog.Infof("%s: checking if machine is past replacement deletion deadline", r.machine.Name)
			deletePastDeadline, err := r.checkMachineDeadline(machineDeleteDeadlineMinutes, machineReplacementCondition.LastTransitionTime.Format(time.RFC3339))
			if err != nil {
				return fmt.Errorf("failed calculating delete deadline with error: %q", err)
			} else if deletePastDeadline {
				// If machine has failed to be replaced by deadline, update status and return an error
				klog.Warningf("%s: machine failed to delete for replacement within deadline", r.machine.Name)
				r.providerStatus.Conditions = reconcileProviderConditions(r.providerStatus.Conditions, ibmcloudproviderv1.IBMCloudMachineProviderCondition{
					Type:    ibmcloudproviderv1.MachineReplacement,
					Reason:  ibmcloudproviderv1.MachineReplacementFailed,
					Message: machineReplacementFailedMessageCondition,
					Status:  apicorev1.ConditionTrue,
				})
				return machinecontroller.DeleteMachine("%s: machine failed to delete within %d minute deadline for replacement", r.machine.Name, machineDeleteDeadlineMinutes)
			}
			klog.Infof("%s: waiting for stuck machine to be deleted prior to replacement", r.machine.Name)
			return nil
		}
	}

	// Check whether the machine remains in Provisioned state but not Running for more than 'machineReplaceDeadlineMinutes'
	// Attempt to mitigate https://issues.redhat.com/browse/OCPBUGS-1327
	// Bypass check if machine statuses do not match this expected case
	if newInstance.Status != nil && *newInstance.Status == ibmStatusRunning && r.machine.Status.Phase != nil && *r.machine.Status.Phase == machinev1.PhaseProvisioned {
		// Check whether a machine replacement condition already exists
		if machineReplacementCondition := conditionTypeCheck(r.providerStatus.Conditions, ibmcloudproviderv1.MachineReplacement); machineReplacementCondition != nil {
			// If the replacement condition is already in progress or completed or failed, we will not make a second replacement attempt, only if one was requested by machine isn't deleted (failed API delete call)
			if machineReplacementCondition.Reason != ibmcloudproviderv1.MachineReplacementRequested {
				klog.Infof("%s: machine replacement can only triggered once, currenetly in: %s", r.machine.Name, machineReplacementCondition.Reason)
				return nil
			}
		}
		klog.Infof("%s: checking if machine is past replacement deadline", r.machine.Name)
		masterMachine := false
		if r.machine.Labels != nil && r.machine.Labels["machine.openshift.io/cluster-api-machine-role"] == "master" {
			masterMachine = true
		}
		if replacementRequired, err := r.checkMachineDeadline(machineReplaceDeadlineMinutes, newInstance.CreatedAt.String()); (err == nil && replacementRequired) && !masterMachine {
			// NOTE(cjschaef): If the machine needs to be replaced:
			// 1. We need to purge Addresses and ProviderID to prevent the machine being marked as Failed, per
			//    https://github.com/openshift/machine-api-operator/blob/6397450f3464ffb875f43011ed8ad7428e50f881/pkg/controller/machine/controller.go#L348-L362
			// 2. We add a MachineReplaced ProviderStatus, to track the deletion and replacement of the machine
			// 3. We delete the machine via IBM Cloud API
			// Any failure in one of these steps, should result in returning back to this code block to try again (PatchMachine or delete failure)
			klog.Warningf("%s: attempting to replace stuck machine", r.machine.Name)
			// Remove the machine's Addresses and ProviderID since we are replacing the machine
			klog.Infof("%s: clearing machine's previous data for replacement machine", r.machine.Name)
			r.machine.Status.Addresses = make([]apicorev1.NodeAddress, 0)
			r.machine.Spec.ProviderID = nil
			// Attempt to update the machine config with this data purge, to prevent failures
			if patchErr := r.PatchMachine(); patchErr != nil {
				return fmt.Errorf("failed to update machine date purge: %q", patchErr)
			}
			// Update status that machine is being replaced
			klog.Infof("%s: updating provider status for replacement requested", r.machine.Name)
			r.providerStatus.Conditions = reconcileProviderConditions(r.providerStatus.Conditions, ibmcloudproviderv1.IBMCloudMachineProviderCondition{
				Type:    ibmcloudproviderv1.MachineReplacement,
				Reason:  ibmcloudproviderv1.MachineReplacementRequested,
				Message: machineReplacementRequestedMessageCondition,
				Status:  apicorev1.ConditionTrue,
			})
			// Attempt to update the Machine config with this ProviderStatus, to track the machine deletion
			if patchErr := r.PatchMachine(); patchErr != nil {
				return fmt.Errorf("failed to update machine with replacement status: %q", patchErr)
			}
			// Finally, attempt to delete the stuck machine
			klog.Infof("%s: deleting machine for replacement", r.machine.Name)
			deleteErr := r.delete()
			// Determine whether the deletion attempt was made and successful (not nil and a RequeueAfterError was returned)
			if _, okay := deleteErr.(*machinecontroller.RequeueAfterError); okay {
				klog.Infof("%s: machine delete call made successfully, for replacement", r.machine.Name)
				return deleteErr
			}
			return fmt.Errorf("attempt to delete stuck machine failed: %q", deleteErr)

		}
	}

	// Update Machine Status Addresses
	ipAddr := *newInstance.PrimaryNetworkInterface.PrimaryIP.Address
	if ipAddr != "" {
		networkAddresses := []apicorev1.NodeAddress{{Type: apicorev1.NodeInternalDNS, Address: r.machine.Name}}
		networkAddresses = append(networkAddresses, apicorev1.NodeAddress{Type: apicorev1.NodeInternalIP, Address: ipAddr})
		r.machine.Status.Addresses = networkAddresses
	} else {
		return fmt.Errorf("could not get the primary ipv4 address of instance: %v", newInstance.Name)
	}

	clusterID := r.machine.Labels[machinev1.MachineClusterIDLabel]
	accountID, err := r.ibmClient.GetAccountID()
	if err != nil {
		return fmt.Errorf("get account id failed with an error: %q", err)
	}
	// Follow same providerID format as the cloud-provider-ibm
	// https://github.com/openshift/cloud-provider-ibm/blob/e30391202c3f02694b2f5b3c2d73cb560d9c133d/ibm/ibm_instances.go#L113-L114
	providerID := fmt.Sprintf("ibm://%s///%s/%s", accountID, clusterID, *newInstance.ID)
	currProviderID := r.machine.Spec.ProviderID

	// Provider ID check and update
	if currProviderID != nil && *currProviderID == providerID {
		klog.Infof("%s: provider id already set in the machine Spec with value:%s", r.machine.Name, *currProviderID)
	} else {
		r.machine.Spec.ProviderID = &providerID
		klog.Infof("%s: provider id set at machine spec: %s", r.machine.Name, providerID)
	}

	// Set providerStatus in machine
	r.providerStatus.InstanceState = newInstance.Status
	r.providerStatus.InstanceID = newInstance.ID

	// Update conditions
	conditionSuccess := ibmcloudproviderv1.IBMCloudMachineProviderCondition{
		Type:    ibmcloudproviderv1.MachineCreated,
		Reason:  ibmcloudproviderv1.MachineCreationSucceeded,
		Message: machineCreationSucceedMessageCondition,
		Status:  apicorev1.ConditionTrue,
	}
	r.providerStatus.Conditions = reconcileProviderConditions(r.providerStatus.Conditions, conditionSuccess)
	// If the machine was being replaced, update the status that the replacement completed
	if conditionTypeCheck(r.providerStatus.Conditions, ibmcloudproviderv1.MachineReplacement) != nil {
		r.providerStatus.Conditions = reconcileProviderConditions(r.providerStatus.Conditions, ibmcloudproviderv1.IBMCloudMachineProviderCondition{
			Type:    ibmcloudproviderv1.MachineReplacement,
			Reason:  ibmcloudproviderv1.MachineReplacementCompleted,
			Message: machineReplacementCompletedMessageCondition,
			Status:  apicorev1.ConditionTrue,
		})
	}

	// Update labels & Annotations
	r.setMachineCloudProviderSpecifics(newInstance)

	// Requeue if status is not Running
	if *newInstance.Status != ibmStatusRunning {
		klog.Infof("%s: machine status is %q, requeuing...", r.machine.Name, *newInstance.Status)
		return &machinecontroller.RequeueAfterError{RequeueAfter: requeueAfterSeconds * time.Second}
	}
	return nil
}

// checkMachineDeadline will check whether a deadline has been passed from a RFC3339 formatted start time
func (r *Reconciler) checkMachineDeadline(deadline time.Duration, startTimeRaw string) (bool, error) {
	userData, err := r.getUserData()
	if err != nil {
		klog.Warningf("%s: failure collecting user data: %v", r.machine.Name, err)
		return false, err
	}
	var ignitionConfig igntypes.Config
	if err := json.Unmarshal([]byte(userData), &ignitionConfig); err != nil {
		klog.Warningf("%s: failure attempting to unmarshal UserData: %v", r.machine.Name, err)
		return false, err
	}

	// Only check machines where the Ignition Config requires fetching additional configuration from an Https source
	if len(ignitionConfig.Ignition.Config.Merge) == 1 && ignitionConfig.Ignition.Config.Merge[0].Source != nil && strings.HasPrefix(*ignitionConfig.Ignition.Config.Merge[0].Source, httpsPrefix) {
		startTime, err := time.Parse(time.RFC3339, startTimeRaw)
		if err != nil {
			klog.Warningf("%s: failure parsing start time for %s minute deadline check: %q", r.machine.Name, deadline, startTimeRaw)
			return false, err
		}

		// Calcuclate deadline and current time
		deadlineTime := startTime.Add(time.Minute * deadline)
		now := time.Now().UTC()

		// If current time is not before the deadline, it fails the check
		if !now.Before(deadlineTime) {
			klog.Infof("%s: machine is past %d minute deadline", r.machine.Name, deadline)
			return true, nil
		}
		klog.Infof("%s: machine is not past %d minute deadline", r.machine.Name, deadline)
		return false, nil
	}
	klog.Infof("%s: machine ignition config does not require source data", r.machine.Name)
	return false, nil
}

// setMachineCloudProviderSpecifics updates Machine resource labels and Annotations
func (r *Reconciler) setMachineCloudProviderSpecifics(instance *vpcv1.Instance) {
	// Make sure machine labels are present before any updates
	if r.machine.Labels == nil {
		r.machine.Labels = make(map[string]string)
	}

	// Make sure machine Annotations are present before any updates
	if r.machine.Annotations == nil {
		r.machine.Annotations = make(map[string]string)
	}

	// Update annotations
	r.machine.Annotations[machinecontroller.MachineInstanceStateAnnotationName] = *instance.Status

	// Update labels
	r.machine.Labels[machinecontroller.MachineRegionLabelName] = r.providerSpec.Region
	r.machine.Labels[machinecontroller.MachineAZLabelName] = r.providerSpec.Zone
	r.machine.Labels[machinecontroller.MachineInstanceTypeLabelName] = r.providerSpec.Profile

}
