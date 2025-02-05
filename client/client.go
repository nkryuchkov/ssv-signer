package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ssvlabs/ssv-signer/server"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) *Client {
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) AddValidator(encryptedShare []byte, validatorPubKey string) error {
	url := fmt.Sprintf("%s/v1/validators/add", c.baseURL)

	requestBody := map[string]interface{}{
		"encrypted_share":  encryptedShare,
		"validator_pubkey": validatorPubKey,
	}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) RemoveValidator(sharePubKey string) error {
	url := fmt.Sprintf("%s/v1/validators/remove", c.baseURL)

	requestBody := map[string]string{
		"share_pubkey": sharePubKey,
	}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) Sign(sharePubKey string, payload interface{}) (string, error) {
	url := fmt.Sprintf("%s/v1/validators/sign", c.baseURL)

	requestBody := map[string]interface{}{
		"share_pubkey": sharePubKey,
		"object":       payload,
	}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var response struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return response.Signature, nil
}

func (c *Client) GetOperatorIdentity() (string, error) {
	url := fmt.Sprintf("%s/v1/operator/identity", c.baseURL)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var result server.OperatorIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode operator identity: %w", err)
	}

	return result.PublicKey, nil
}

func (c *Client) OperatorSign(payload []byte) ([]byte, error) {
	url := fmt.Sprintf("%s/v1/operator/sign", c.baseURL)

	requestBody := server.OperatorSignRequest{Payload: payload}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	var result server.OperatorSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result.Signature, nil
}
