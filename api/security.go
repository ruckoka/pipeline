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

package api

import (
	"fmt"
	"net/http"

	"github.com/banzaicloud/anchore-image-validator/pkg/apis/security/v1alpha1"
	clientV1alpha1 "github.com/banzaicloud/anchore-image-validator/pkg/clientset/v1alpha1"
	"github.com/banzaicloud/pipeline/helm"
	pkgCommmon "github.com/banzaicloud/pipeline/pkg/common"
	"github.com/banzaicloud/pipeline/pkg/security"
	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
)

func init() {
	v1alpha1.AddToScheme(scheme.Scheme)
}

func getSecurityClient(c *gin.Context) *clientV1alpha1.SecurityV1Alpha1Client {
	kubeConfig, ok := GetK8sConfig(c)
	if !ok {
		return nil
	}
	config, err := helm.GetK8sClientConfig(kubeConfig)
	if err != nil {
		log.Errorf("Error getting K8s config: %s", err.Error())
		c.JSON(http.StatusBadRequest, pkgCommmon.ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Error getting K8s config",
			Error:   err.Error(),
		})
		return nil
	}

	securityClientSet, err := clientV1alpha1.SecurityConfig(config)
	if err != nil {
		log.Errorf("Error getting SecurityClient: %s", err.Error())
		c.JSON(http.StatusBadRequest, pkgCommmon.ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Error getting SecurityClient",
			Error:   err.Error(),
		})
		return nil
	}
	return securityClientSet
}

// GetScanLog returns image scan results for all deployments
func GetScanLog(c *gin.Context) {
	securityClientSet := getSecurityClient(c)
	if securityClientSet == nil {
		return
	}

	audits, err := securityClientSet.Audits(metav1.NamespaceAll).List(metav1.ListOptions{})
	if err != nil {
		err := errors.Wrap(err, "Error during request processing")
		log.Error(err.Error())
		httpStatusCode := http.StatusInternalServerError
		c.JSON(httpStatusCode, pkgCommmon.ErrorResponse{
			Code:    httpStatusCode,
			Message: "Error getting scanlogs",
			Error:   err.Error(),
		})
		return
	}

	scanLogList := make([]security.ScanLogItem, 0)
	for _, audit := range audits.Items {
		scanLog := security.ScanLogItem{
			ReleaseName: audit.Spec.ReleaseName,
			Resource:    audit.Spec.Resource,
			Action:      audit.Spec.Action,
			Image:       audit.Spec.Image,
			Result:      audit.Spec.Result,
		}
		scanLogList = append(scanLogList, scanLog)
	}

	c.JSON(http.StatusOK, scanLogList)

}

// GetWhiteLists returns whitelists for all deployments
func GetWhiteLists(c *gin.Context) {
	securityClientSet := getSecurityClient(c)
	if securityClientSet == nil {
		return
	}

	whitelists, err := securityClientSet.Whitelists(metav1.NamespaceAll).List(metav1.ListOptions{})
	if err != nil {
		err := errors.Wrap(err, "Error during request processing")
		log.Error(err.Error())
		httpStatusCode := http.StatusInternalServerError
		c.JSON(httpStatusCode, pkgCommmon.ErrorResponse{
			Code:    httpStatusCode,
			Message: "Error getting whitelists",
			Error:   err.Error(),
		})
		return
	}

	releaseWhitelist := make([]security.ReleaseWhiteListItem, 0)
	for _, whitelist := range whitelists.Items {
		whitelistItem := security.ReleaseWhiteListItem{
			Name:        whitelist.Name,
			ReleaseName: whitelist.Spec.ReleaseName,
			Owner:       whitelist.Spec.Creator,
			Reason:      whitelist.Spec.Reason,
		}
		releaseWhitelist = append(releaseWhitelist, whitelistItem)
	}

	c.JSON(http.StatusOK, releaseWhitelist)

}

// CreateWhiteList creates a whitelist for a deployment
func CreateWhiteList(c *gin.Context) {
	securityClientSet := getSecurityClient(c)
	if securityClientSet == nil {
		return
	}

	var whitelistCreateRequest *security.ReleaseWhiteListItem
	err := c.BindJSON(&whitelistCreateRequest)
	if err != nil {
		err := errors.Wrap(err, "Error parsing request:")
		log.Error(err.Error())
		c.JSON(http.StatusBadRequest, pkgCommmon.ErrorResponse{
			Code:    http.StatusBadRequest,
			Message: "Error during parsing request!",
			Error:   errors.Cause(err).Error(),
		})
		return
	}

	whitelist := v1alpha1.WhiteListItem{
		TypeMeta: metav1.TypeMeta{
			Kind:       "WhiteListItem",
			APIVersion: fmt.Sprintf("%v/%v", v1alpha1.GroupName, v1alpha1.GroupVersion),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: whitelistCreateRequest.Name,
		},
		Spec: v1alpha1.WhiteListSpec{
			ReleaseName: whitelistCreateRequest.ReleaseName,
			Creator:     whitelistCreateRequest.Owner,
			Reason:      whitelistCreateRequest.Reason,
		},
	}
	_, err = securityClientSet.Whitelists(metav1.NamespaceDefault).Create(&whitelist)
	if err != nil {
		err := errors.Wrap(err, "Error during request processing")
		log.Error(err.Error())
		httpStatusCode := http.StatusInternalServerError
		c.JSON(httpStatusCode, pkgCommmon.ErrorResponse{
			Code:    httpStatusCode,
			Message: "Error creating whitelist",
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, "created")

}

// DeleteWhiteList deletes a whitelist
func DeleteWhiteList(c *gin.Context) {
	name := c.Param("name")
	if len(name) == 0 {
		httpStatusCode := http.StatusBadRequest
		c.JSON(httpStatusCode, pkgCommmon.ErrorResponse{
			Code:    httpStatusCode,
			Message: "WhiteList name is required!",
			Error:   "WhiteList name is required!",
		})
		return
	}

	securityClientSet := getSecurityClient(c)
	if securityClientSet == nil {
		return
	}

	err := securityClientSet.Whitelists(metav1.NamespaceDefault).Delete(name, &metav1.DeleteOptions{})
	if err != nil {
		err := errors.Wrap(err, "Error during request processing")
		log.Error(err.Error())
		httpStatusCode := http.StatusInternalServerError
		c.JSON(httpStatusCode, pkgCommmon.ErrorResponse{
			Code:    httpStatusCode,
			Message: "Error deleting whitelist",
			Error:   err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, "deleted")
}