package enforce

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HTTPOrchestratorLB is a minimal client for the Bridge orchestrator's
// token-factory LoadBalancer endpoints. It is the "muscle" for ingress ALLOW/DENY:
//
//	POST   /tenants/{tenant}/token-factory/endpoints/{id}/loadbalancer   -> provision (returns VIP)
//	DELETE /tenants/{tenant}/token-factory/endpoints/{id}/loadbalancer   -> deprovision
//
// NOTE (scaffold): identity/auth headers are environment-specific. Wire the real
// service-account / session here before production use.
type HTTPOrchestratorLB struct {
	BaseURL string
	Client  *http.Client
	// AuthHeader, if set, is attached to every request (e.g. "Bearer <token>").
	AuthHeader string
}

func NewHTTPOrchestratorLB(baseURL string) *HTTPOrchestratorLB {
	return &HTTPOrchestratorLB{
		BaseURL: strings.TrimRight(baseURL, "/"),
		Client:  &http.Client{Timeout: 30 * time.Second},
	}
}

type provisionReq struct {
	ClusterID        string `json:"clusterID"`
	Hostname         string `json:"hostname"`
	EnableExternalIP bool   `json:"enableExternalIP"`
}

type provisionResp struct {
	IPAddress string `json:"ipAddress"`
}

func (c *HTTPOrchestratorLB) ProvisionEndpointLB(ctx context.Context, tenantID, clusterID, endpointID, hostname string, enableExternalIP bool) (string, error) {
	url := fmt.Sprintf("%s/tenants/%s/token-factory/endpoints/%s/loadbalancer", c.BaseURL, tenantID, endpointID)
	body, _ := json.Marshal(provisionReq{ClusterID: clusterID, Hostname: hostname, EnableExternalIP: enableExternalIP})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c.applyAuth(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("provision endpoint LB: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		// 4xx: the orchestrator judged and refused the request -> do not retry blindly.
		if resp.StatusCode >= 400 && resp.StatusCode < 500 {
			return "", &RefusedError{StatusCode: resp.StatusCode, Message: message(raw)}
		}
		return "", fmt.Errorf("orchestrator refused provisioning: %s - %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var decoded provisionResp
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		return "", fmt.Errorf("decode orchestrator response: %w", err)
	}
	return decoded.IPAddress, nil
}

func (c *HTTPOrchestratorLB) DeprovisionEndpointLB(ctx context.Context, tenantID, clusterID, endpointID string) error {
	url := fmt.Sprintf("%s/tenants/%s/token-factory/endpoints/%s/loadbalancer?clusterId=%s",
		c.BaseURL, tenantID, endpointID, clusterID)
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	if err != nil {
		return err
	}
	c.applyAuth(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return fmt.Errorf("deprovision endpoint LB: %w", err)
	}
	defer resp.Body.Close()

	// 404 is treated as already-gone (idempotent teardown).
	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent, http.StatusNotFound:
		return nil
	default:
		raw, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("orchestrator refused deprovisioning: %s - %s", resp.Status, strings.TrimSpace(string(raw)))
	}
}

func (c *HTTPOrchestratorLB) applyAuth(req *http.Request) {
	if c.AuthHeader != "" {
		req.Header.Set("Authorization", c.AuthHeader)
	}
}

func message(raw []byte) string {
	var body struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &body); err == nil && strings.TrimSpace(body.Message) != "" {
		return strings.TrimSpace(body.Message)
	}
	return strings.TrimSpace(string(raw))
}
