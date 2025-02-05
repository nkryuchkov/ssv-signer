package keystore

import (
	"fmt"
	"os"

	"github.com/ssvlabs/ssv/operator/keys"
	"github.com/ssvlabs/ssv/operator/keystore"
)

func LoadOperatorKeystore(encryptedPrivateKeyFile, passwordFile string) (keys.OperatorPrivateKey, error) {
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

	return operatorPrivKey, nil
}
