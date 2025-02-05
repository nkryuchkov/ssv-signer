package web3signer

type MockClient struct{}

func NewMockClient(string) (*MockClient, error) {
	return &MockClient{}, nil
}

func (MockClient) ImportKeystore(keystore, keystorePassword string) error {
	return nil
}

func (MockClient) DeleteKeystore(pubkey string) error {
	return nil
}

func (MockClient) Sign(pubkey string, payload interface{}) (string, error) {
	return "", nil
}
