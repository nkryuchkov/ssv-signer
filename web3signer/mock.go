package web3signer

type MockClient struct{}

func NewMockClient(string) (*MockClient, error) {
	return &MockClient{}, nil
}

func (MockClient) ImportKeystore(keystore, keystorePassword string) error {
	return nil
}

func (MockClient) DeleteKeystore(sharePubKey []byte) error {
	return nil
}

func (MockClient) Sign(sharePubKey []byte, payload []byte) ([]byte, error) {
	return nil, nil
}
