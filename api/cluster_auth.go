// Copyright © 2019 Banzai Cloud
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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	k8s_client "k8s.io/client-go/tools/clientcmd"
	k8s_api "k8s.io/client-go/tools/clientcmd/api"
)

type ClusterAuthAPI struct {
	// Does the provider use "offline_access" scope to request a refresh token
	// or does it use "access_type=offline" (e.g. Google)?
	offlineAsScope bool

	clientID     string
	clientSecret string
	redirectURI  string

	client *http.Client

	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier

	clusterManager ClusterManager
}

func NewAPI() (*ClusterAuthAPI, error) {

	a := ClusterAuthAPI{client: http.DefaultClient}

	a.clientID = viper.GetString("auth.clientid")
	a.clientSecret = viper.GetString("auth.clientsecret")
	issuerURL := viper.GetString("auth.dexURL")
	a.redirectURI = viper.GetString("auth.redirectURL")

	_, err := url.Parse(a.redirectURI)
	if err != nil {
		return nil, fmt.Errorf("parse redirect-uri: %v", err)
	}

	ctx := oidc.ClientContext(context.Background(), a.client)
	provider, err := oidc.NewProvider(ctx, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("Failed to query provider %q: %v", issuerURL, err)
	}

	var s struct {
		// What scopes does a provider support?
		//
		// See: https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := provider.Claims(&s); err != nil {
		return nil, fmt.Errorf("Failed to parse provider scopes_supported: %v", err)
	}

	if len(s.ScopesSupported) == 0 {
		// scopes_supported is a "RECOMMENDED" discovery claim, not a required
		// one. If missing, assume that the provider follows the spec and has
		// an "offline_access" scope.
		a.offlineAsScope = true
	} else {
		// See if scopes_supported has the "offline_access" scope.
		a.offlineAsScope = func() bool {
			for _, scope := range s.ScopesSupported {
				if scope == oidc.ScopeOfflineAccess {
					return true
				}
			}
			return false
		}()
	}

	a.provider = provider
	a.verifier = provider.Verifier(&oidc.Config{ClientID: a.clientID})

	return &a, nil
}

// This will be called back at $HOST/auth/dex/cluster/callback
func (a *ClusterAuthAPI) DexCallback(c *gin.Context) {

	var (
		err   error
		token *oauth2.Token
	)

	r := c.Request

	ctx := oidc.ClientContext(r.Context(), a.client)
	oauth2Config := a.oauth2Config(nil)
	switch r.Method {
	case "GET":
		// Authorization redirect callback from OAuth2 auth flow.
		if errMsg := r.FormValue("error"); errMsg != "" {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("%s: %s", errMsg, r.FormValue("error_description")))
			return
		}
		code := r.FormValue("code")
		if code == "" {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("no code in request: %q", r.Form))
			return
		}
		if state := r.FormValue("state"); state != exampleAppState {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("expected state %q got %q", exampleAppState, state))
			return
		}
		token, err = oauth2Config.Exchange(ctx, code)
	case "POST":
		// Form request from frontend to refresh a token.
		refresh := r.FormValue("refresh_token")
		if refresh == "" {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("no refresh_token in request: %q", r.Form))
			return
		}
		t := &oauth2.Token{
			RefreshToken: refresh,
			Expiry:       time.Now().Add(-time.Hour),
		}
		token, err = oauth2Config.TokenSource(ctx, t).Token()
	default:
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("method not implemented: %s", r.Method))
		return
	}

	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get token: %v", err))
		return
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("no id_token in token response"))
		return
	}

	idToken, err := a.verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to verify ID token: %v", err))
		return
	}
	var claims json.RawMessage
	idToken.Claims(&claims)

	buff := new(bytes.Buffer)
	json.Indent(buff, []byte(claims), "", "  ")
	var m claim
	err = json.Unmarshal(claims, &m)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to read claims: %v", err))
		return
	}

	err = a.updateKubeConfig(rawIDToken, token.RefreshToken, m)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to update kubeconfig: %v", err))
		return
	}

	// renderToken(c.Writer, a.redirectURI, rawIDToken, token.RefreshToken, buff.Bytes())

	fmt.Printf("Login Succeeded as %s\n", m.Email)
	fmt.Printf("ID Token: %s\n", rawIDToken)
	fmt.Printf("Refresh Token: %s\n", token.RefreshToken)
	fmt.Printf("Claims: %s\n", string(claims))
}

func (api *ClusterAuthAPI) Login(c *gin.Context) {
	var scopes []string

	clusterID := c.Param("id")

	var authCodeURL string
	scopes = append(scopes, "groups", "openid", "profile", "email")
	if api.offlineAsScope {
		scopes = append(scopes, "offline_access")
		authCodeURL = api.oauth2Config(scopes).AuthCodeURL(exampleAppState)
	} else {
		authCodeURL = api.oauth2Config(scopes).AuthCodeURL(exampleAppState, oauth2.AccessTypeOffline)
	}

	c.Redirect(http.StatusSeeOther, authCodeURL)
}

type claim struct {
	Iss           string `json:"iss"`
	Sub           string `json:"sub"`
	Aud           string `json:"aud"`
	Exp           int    `json:"exp"`
	Iat           int    `json:"iat"`
	AtHash        string `json:"at_hash"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
}

type debugTransport struct {
	t http.RoundTripper
}

func (d debugTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	reqDump, err := httputil.DumpRequest(req, true)
	if err != nil {
		return nil, err
	}
	log.Printf("%s", reqDump)

	resp, err := d.t.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	respDump, err := httputil.DumpResponse(resp, true)
	if err != nil {
		resp.Body.Close()
		return nil, err
	}
	log.Printf("%s", respDump)
	return resp, nil
}

func (a *ClusterAuthAPI) oauth2Config(scopes []string) *oauth2.Config {
	return &oauth2.Config{
		ClientID:     a.clientID,
		ClientSecret: a.clientSecret,
		Endpoint:     a.provider.Endpoint(),
		Scopes:       scopes,
		RedirectURL:  a.redirectURI,
	}
}

func (a *ClusterAuthAPI) updateKubeConfig(IDToken string, refreshToken string, claims claim) error {
	var config *k8s_api.Config
	var outputFilename string
	var err error

	clientConfigLoadingRules := k8s_client.NewDefaultClientConfigLoadingRules()

	config, err = clientConfigLoadingRules.Load()
	outputFilename = k8s_client.RecommendedHomeFile
	if !k8s_api.IsConfigEmpty(config) {
		outputFilename = clientConfigLoadingRules.GetDefaultFilename()
	}
	if err != nil {
		return err
	}

	authInfo := k8s_api.NewAuthInfo()
	if conf, ok := config.AuthInfos[claims.Email]; ok {
		authInfo = conf
	}

	authInfo.AuthProvider = &k8s_api.AuthProviderConfig{
		Name: "oidc",
		Config: map[string]string{
			"client-id":      a.clientID,
			"client-secret":  a.clientSecret,
			"id-token":       IDToken,
			"refresh-token":  refreshToken,
			"idp-issuer-url": claims.Iss,
		},
	}

	config.AuthInfos[claims.Email] = authInfo

	fmt.Printf("Writing config to %s\n", outputFilename)
	err = k8s_client.WriteToFile(*config, outputFilename)
	if err != nil {
		return err
	}
	return nil
}

func open(url string) error {

	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
	case "darwin":
		cmd = "open"
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
	}
	args = append(args, url)
	return exec.Command(cmd, args...).Start()
}
