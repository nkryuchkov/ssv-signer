package web3signer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	baseURL    string
	httpClient *http.Client
}

func NewClient(baseURL string) (*Client, error) {
	baseURL = strings.TrimRight(baseURL, "/")

	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}, nil
}

// ImportKeystore adds a key to Web3Signer using https://consensys.github.io/web3signer/web3signer-eth2.html#tag/Keymanager/operation/KEYMANAGER_IMPORT
func (c *Client) ImportKeystore(keystore, keystorePassword string) error {
	payload := struct {
		Keystores []string
		Passwords []string
	}{
		Keystores: []string{keystore},
		Passwords: []string{keystorePassword},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal import payload: %w", err)
	}

	url := fmt.Sprintf("%s/eth/v1/keystores", c.baseURL)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create import request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("import request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// TODO parse the response to confirm successful import
	return nil
}

// DeleteKeystore removes a key from Web3Signer using https://consensys.github.io/web3signer/web3signer-eth2.html#operation/KEYMANAGER_DELETE
func (c *Client) DeleteKeystore(pubkey string) error {
	if !strings.HasPrefix(pubkey, "0x") {
		pubkey = "0x" + pubkey
	}
	url := fmt.Sprintf("%s/eth/v1/keystores/%s", c.baseURL, pubkey)

	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("create delete request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("delete request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	return nil
}

func (c *Client) Sign(pubkey string, payload interface{}) (string, error) {
	// TODO: Note: public key is share public key and not validator public key
	// TODO: check the note above

	if !strings.HasPrefix(pubkey, "0x") {
		pubkey = "0x" + pubkey
	}

	url := fmt.Sprintf("%s/eth/v1/eth2/sign/%s", c.baseURL, pubkey)

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal sign payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("create sign request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("sign request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", fmt.Errorf("unexpected status code %d", resp.StatusCode)
	}

	// TODO: check response format
	var jsonResp struct {
		Signature string `json:"signature"`
	}
	respData, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(respData, &jsonResp); err != nil {
		return "", fmt.Errorf("unmarshal sign response: %w", err)
	}

	return jsonResp.Signature, nil
}
