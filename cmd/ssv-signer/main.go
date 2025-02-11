package main

import (
	"log"

	"github.com/alecthomas/kong"
	"github.com/ssvlabs/ssv-signer/keys"
	"github.com/ssvlabs/ssv-signer/server"
	"github.com/ssvlabs/ssv-signer/web3signer"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type CLI struct {
	ListenAddr         string `env:"LISTEN_ADDR" default:":8080"`
	Web3SignerEndpoint string `env:"WEB3SIGNER_ENDPOINT"`
	PrivateKey         string `env:"PRIVATE_KEY"`
	PrivateKeyFile     string `env:"PRIVATE_KEY_FILE"`
	PasswordFile       string `env:"PASSWORD_FILE"`
}

func main() {
	cli := CLI{}
	_ = kong.Parse(&cli)

	logger, err := zap.NewDevelopment()
	if err != nil {
		log.Fatal(err)
	}
	defer logger.Sync()

	logger.Debug("Starting ssv-signer",
		zap.String("listen_addr", cli.ListenAddr),
		zap.String("web3signer_endpoint", cli.Web3SignerEndpoint),
		zap.String("private_key_file", cli.PrivateKeyFile),
		zap.String("password_file", cli.PasswordFile),
		zap.Bool("got_private_key", cli.PrivateKey != ""),
	)

	if cli.PrivateKey == "" && cli.PrivateKeyFile == "" {
		logger.Fatal("either private key or private key file must be set, found none")
	}

	if cli.PrivateKey != "" && cli.PrivateKeyFile != "" {
		logger.Fatal("either private key or private key file must be set, found both")
	}

	var operatorPrivateKey keys.OperatorPrivateKey
	if cli.PrivateKey != "" {
		operatorPrivateKey, err = keys.PrivateKeyFromString(cli.PrivateKey)
		if err != nil {
			logger.Fatal("failed to parse private key", zap.Error(err))
		}
	} else {
		operatorPrivateKey, err = keys.LoadOperatorKeystore(cli.PrivateKeyFile, cli.PasswordFile)
		if err != nil {
			logger.Fatal("failed to load operator key from file", zap.Error(err))
		}
	}

	web3SignerClient, err := web3signer.New(cli.Web3SignerEndpoint)
	if err != nil {
		logger.Fatal("create web3signer client", zap.Error(err))
	}

	logger.Info("Starting ssv-signer server", zap.String("addr", cli.ListenAddr))

	srv := server.New(logger, operatorPrivateKey, web3SignerClient)
	if err := fasthttp.ListenAndServe(cli.ListenAddr, srv.Handler()); err != nil {
		logger.Fatal("failed to start server", zap.Error(err))
	}
}
