package web3signer

type Interface interface {
	ImportKeystore(keystore, keystorePassword string) error
	DeleteKeystore(pubkey string) error
	Sign(pubkey string, payload interface{}) (string, error)
}
