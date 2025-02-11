package keys

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/ssvlabs/eth2-key-manager/encryptor/keystorev4"
)

func LoadOperatorKeystore(encryptedPrivateKeyFile, passwordFile string) (OperatorPrivateKey, error) {
	// nolint: gosec
	encryptedJSON, err := os.ReadFile(encryptedPrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("could not read PEM file: %w", err)
	}

	// nolint: gosec
	keyStorePassword, err := os.ReadFile(passwordFile)
	if err != nil {
		return nil, fmt.Errorf("could not read password file: %w", err)
	}

	decryptedKeystore, err := DecryptKeystore(encryptedJSON, string(keyStorePassword))
	if err != nil {
		return nil, fmt.Errorf("could not decrypt operator private key keystore: %w", err)
	}
	operatorPrivKey, err := PrivateKeyFromBytes(decryptedKeystore)
	if err != nil {
		return nil, fmt.Errorf("could not extract operator private key from file: %w", err)
	}

	return operatorPrivKey, nil
}

func GenerateShareKeystore(sharePrivateKey []byte) (string, string, error) {
	passphrase := "" // TODO: set passphrase
	encryptedKeystoreJSON, err := keystorev4.New().Encrypt(sharePrivateKey, passphrase)
	if err != nil {
		return "", "", fmt.Errorf("encrypt private key: %w", err)
	}

	encryptedData, err := json.Marshal(encryptedKeystoreJSON)
	if err != nil {
		return "", "", fmt.Errorf("marshal encrypted keystore: %w", err)
	}

	return string(encryptedData), passphrase, nil
}

// DecryptKeystore decrypts a keystore JSON file using the provided password.
func DecryptKeystore(encryptedJSONData []byte, password string) ([]byte, error) {
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("Password required for decrypting keystore")
	}

	// Unmarshal the JSON-encoded data
	var data map[string]interface{}
	if err := json.Unmarshal(encryptedJSONData, &data); err != nil {
		return nil, fmt.Errorf("parse JSON data: %w", err)
	}

	// Decrypt the private key using keystorev4
	decryptedBytes, err := keystorev4.New().Decrypt(data, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}

	return decryptedBytes, nil
}

// EncryptKeystore encrypts a private key using the provided password, adds in the public key and returns the encrypted keystore JSON data.
func EncryptKeystore(privkey []byte, pubKeyBase64, password string) ([]byte, error) {
	if strings.TrimSpace(password) == "" {
		return nil, fmt.Errorf("Password required for encrypting keystore")
	}

	// Encrypt the private key using keystorev4
	encryptedKeystoreJSON, err := keystorev4.New().Encrypt(privkey, password)
	if err != nil {
		return nil, fmt.Errorf("encrypt private key: %w", err)
	}

	encryptedKeystoreJSON["pubKey"] = pubKeyBase64

	encryptedData, err := json.Marshal(encryptedKeystoreJSON)
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted keystore: %w", err)
	}

	return encryptedData, nil
}
