package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ssvlabs/ssv-signer/server"
	"github.com/ssvlabs/ssv-signer/web3signer"
)

type SSVSignerClient struct {
	baseURL    string
	httpClient *http.Client
}

func New(baseURL string) *SSVSignerClient {
	baseURL = strings.TrimRight(baseURL, "/")

	return &SSVSignerClient{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *SSVSignerClient) AddValidator(encryptedShare, validatorPubKey []byte) error {
	url := fmt.Sprintf("%s/v1/validators/add", c.baseURL)

	requestBody := server.AddValidatorRequest{
		EncryptedSharePrivateKey: encryptedShare,
		ValidatorPublicKey:       validatorPubKey,
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

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBytes))
	}

	return nil
}

func (c *SSVSignerClient) RemoveValidator(sharePubKey []byte) error {
	url := fmt.Sprintf("%s/v1/validators/remove", c.baseURL)

	requestBody := server.RemoveValidatorRequest{SharePublicKey: sharePubKey}

	data, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Errorf("marshal request: %w", err)
	}

	resp, err := c.httpClient.Post(url, "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBytes))
	}

	return nil
}

func (c *SSVSignerClient) Sign(sharePubKey []byte, payload web3signer.SignRequest) (string, error) {
	url := fmt.Sprintf("%s/v1/validators/sign", c.baseURL)

	requestBody := server.ValidatorSignRequest{
		SharePublicKey: sharePubKey,
		Payload:        payload,
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

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBytes))
	}

	var response struct {
		Signature string `json:"signature"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}

	return response.Signature, nil
}

func (c *SSVSignerClient) GetOperatorIdentity() (string, error) {
	url := fmt.Sprintf("%s/v1/operator/identity", c.baseURL)

	resp, err := c.httpClient.Get(url)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBytes))
	}

	var result server.OperatorIdentityResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode operator identity: %w", err)
	}

	return result.PublicKey, nil
}

func (c *SSVSignerClient) OperatorSign(payload []byte) ([]byte, error) {
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

	if resp.StatusCode != http.StatusOK {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code %d: %s", resp.StatusCode, string(respBytes))
	}

	var result server.OperatorSignResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return result.Signature, nil
}
