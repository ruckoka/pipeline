// Copyright © 2018 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package action

import (
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ess"
	"github.com/banzaicloud/pipeline/model"
	pkgErrors "github.com/banzaicloud/pipeline/pkg/errors"
	"github.com/goph/emperror"
	"github.com/sirupsen/logrus"
)

// UpdateACSKNodePoolAction describes the fields used across ACK cluster update operation
type UpdateACSKNodePoolAction struct {
	clusterName string
	log         logrus.FieldLogger
	nodePools   []*model.ACSKNodePoolModel
	context     *ACKContext
	region      string
}

// NewUpdateACSKNodePoolAction creates a new UpdateACSKNodePoolAction
func NewUpdateACSKNodePoolAction(log logrus.FieldLogger, clusterName string, nodepools []*model.ACSKNodePoolModel, clusterContext *ACKContext, region string) *UpdateACSKNodePoolAction {
	return &UpdateACSKNodePoolAction{
		log:         log,
		clusterName: clusterName,
		nodePools:   nodepools,
		context:     clusterContext,
		region:      region,
	}
}

// GetName returns the name of this UpdateACSKNodePoolAction
func (a *UpdateACSKNodePoolAction) GetName() string {
	return "UpdateACSKNodePoolAction"
}

// difference returns the elements in a that aren't in b
func difference(a, b []ess.ScalingInstance) []ess.ScalingInstance {
	mb := map[ess.ScalingInstance]bool{}
	for _, x := range b {
		mb[x] = true
	}
	ab := make([]ess.ScalingInstance, 0)
	for _, x := range a {
		if _, ok := mb[x]; !ok {
			ab = append(ab, x)
		}
	}
	return ab
}

// ExecuteAction executes this UpdateACSKNodePoolAction
func (a *UpdateACSKNodePoolAction) ExecuteAction(input interface{}) (interface{}, error) {
	if len(a.nodePools) != 0 {
		a.log.Infof("EXECUTE UpdateACSKNodePoolAction on cluster, %s", a.context.ClusterID)
		errChan := make(chan error, len(a.nodePools))
		createdInstanceIdsChan := make(chan []string, len(a.nodePools))
		defer close(errChan)
		defer close(createdInstanceIdsChan)

		for _, nodePool := range a.nodePools {
			// TODO: update node pools in parallel once Alibaba ESS API permits running multiple ModifyScalingGroupRequest in parallel
			updateNodePool(a.log, nodePool, a.context.ESSClient, a.region, a.clusterName, createdInstanceIdsChan, errChan)
		}

		caughtErrors := emperror.NewMultiErrorBuilder()
		var createdInstanceIds []string
		var err error

		for i := 0; i < len(a.nodePools); i++ {
			err = <-errChan
			ids := <-createdInstanceIdsChan
			if err != nil {
				caughtErrors.Add(err)
			} else {
				createdInstanceIds = append(createdInstanceIds, ids...)
			}
		}
		err = caughtErrors.ErrOrNil()
		if err != nil {
			return nil, pkgErrors.NewMultiErrorWithFormatter(err)
		}

		if len(createdInstanceIds) != 0 {
			_, err = attachInstancesToCluster(a.log, a.context.ClusterID, createdInstanceIds, a.context.CSClient)
			if err != nil {
				return nil, emperror.With(err, "cluster", a.clusterName)
			}
		}
	}

	r, err := GetClusterDetails(a.context.CSClient, a.context.ClusterID)
	if err != nil {
		return nil, emperror.With(err, "cluster", a.clusterName)
	}

	return r, nil
}
