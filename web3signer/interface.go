package web3signer

type Interface interface {
	ImportKeystore() error // TODO: pass data
	DeleteKeystore(pubkey string) error
	Sign(pubkey string, payload interface{}) (string, error)
}
