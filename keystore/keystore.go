package keystore

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/ssvlabs/eth2-key-manager/encryptor/keystorev4"
	"github.com/ssvlabs/ssv/operator/keys"
	"github.com/ssvlabs/ssv/operator/keystore"
)

type OperatorKeyStore struct {
	PrivKey  keys.OperatorPrivateKey
	Password string
}

func LoadOperatorKeystore(encryptedPrivateKeyFile, passwordFile string) (*OperatorKeyStore, error) {
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

	decryptedKeystore, err := keystore.DecryptKeystore(encryptedJSON, string(keyStorePassword))
	if err != nil {
		return nil, fmt.Errorf("could not decrypt operator private key keystore: %w", err)
	}
	operatorPrivKey, err := keys.PrivateKeyFromBytes(decryptedKeystore)
	if err != nil {
		return nil, fmt.Errorf("could not extract operator private key from file: %w", err)
	}

	return &OperatorKeyStore{
		PrivKey:  operatorPrivKey,
		Password: string(keyStorePassword),
	}, nil
}

func (ks *OperatorKeyStore) GenerateShareKeystore(decryptedShare []byte) (string, string, error) {
	// TODO: Note: keystore private key is the share public key, so accordingly the public key should be share public key as well
	// TODO: should we encrypt ks.PrivKey.Public().Base64()?
	encryptedKeystoreJSON, err := keystorev4.New().Encrypt(ks.PrivKey.Bytes(), ks.Password) // TODO: use another password?
	if err != nil {
		return "", "", fmt.Errorf("encrypt private key: %w", err)
	}

	encryptedKeystoreJSON["share"] = decryptedShare

	encryptedData, err := json.Marshal(encryptedKeystoreJSON)
	if err != nil {
		return "", "", fmt.Errorf("marshal encrypted keystore: %w", err)
	}

	return string(encryptedData), ks.Password, nil
}
