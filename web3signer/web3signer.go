package web3signer

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Web3SignerClient struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string) (*Web3SignerClient, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	return &Web3SignerClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// ImportKeystore adds a key to Web3Signer using https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager/operation/KEYMANAGER_IMPORT
func (c *Web3SignerClient) ImportKeystore(keystore, keystorePassword string) error {
	payload := ImportKeystoreRequest{
		Keystores:          []string{keystore},
		Passwords:          []string{keystorePassword},
		SlashingProtection: "", // TODO
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/eth/v1/keystores", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	var resp ImportKeystoreResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %v", httpResp.StatusCode, resp.Message)
	}

	for i, data := range resp.Data {
		if data.Status != "imported" {
			return fmt.Errorf("unexpected key %d import status: %s", i, data.Status)
		}
	}

	return nil
}

// DeleteKeystore removes a key from Web3Signer using https://consensys.github.io/web3signer/web3signer-eth2.html#operation/KEYMANAGER_DELETE
func (c *Web3SignerClient) DeleteKeystore(sharePubKey []byte) error {
	payload := DeleteKeystoreRequest{
		Pubkeys: []string{hex.EncodeToString(sharePubKey)},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/eth/v1/keystores", c.baseURL)
	req, err := http.NewRequest(http.MethodDelete, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	httpResp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer httpResp.Body.Close()

	respBytes, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}
	var resp DeleteKeystoreResponse
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		return fmt.Errorf("unmarshal response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %d: %v", httpResp.StatusCode, resp.Message)
	}

	for i, data := range resp.Data {
		if data.Status != "deleted" {
			return fmt.Errorf("unexpected key %d delete status: %s", i, data.Status)
		}
	}

	return nil
}

// Sign signs using https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Signing/operation/ETH2_SIGN
func (c *Web3SignerClient) Sign(sharePubKey []byte, payload SignRequest) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal payload: %w", err)
	}

	url := fmt.Sprintf("%s/eth/v1/eth2/sign/%s", c.baseURL, hex.EncodeToString(sharePubKey))
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sign request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// TODO: check response format
	var jsonResp struct {
		Signature string `json:"signature"`
	}
	respData, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(respData, &jsonResp); err != nil {
		return nil, fmt.Errorf("unmarshal sign response: %w", err)
	}

	sigBytes, err := hex.DecodeString(jsonResp.Signature)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}

	return sigBytes, nil
}
