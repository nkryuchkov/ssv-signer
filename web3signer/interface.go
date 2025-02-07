package web3signer

type Interface interface {
	ImportKeystore(keystore, keystorePassword string) error
	DeleteKeystore(sharePubKey []byte) error
	Sign(sharePubKey []byte, payload SignRequest) ([]byte, error)
}
