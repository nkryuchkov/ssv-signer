package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/fasthttp/router"
	"github.com/ssvlabs/ssv-signer/keys"
	"github.com/ssvlabs/ssv-signer/web3signer"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type Server struct {
	logger          *zap.Logger
	operatorPrivKey keys.OperatorPrivateKey
	web3Signer      *web3signer.Web3Signer
	router          *router.Router
	keystorePasswd  string
}

func New(
	logger *zap.Logger,
	operatorPrivKey keys.OperatorPrivateKey,
	web3Signer *web3signer.Web3Signer,
	keystorePasswd string,
) *Server {
	r := router.New()

	server := &Server{
		logger:          logger,
		operatorPrivKey: operatorPrivKey,
		web3Signer:      web3Signer,
		router:          r,
		keystorePasswd:  keystorePasswd,
	}

	r.POST("/v1/validators/add", server.handleAddValidator)
	r.POST("/v1/validators/remove", server.handleRemoveValidator)
	r.POST("/v1/validators/sign/{identifier}", server.handleSignValidator)

	r.GET("/v1/operator/identity", server.handleOperatorIdentity)
	r.POST("/v1/operator/sign", server.handleSignOperator)

	return server
}

func (r *Server) Handler() func(ctx *fasthttp.RequestCtx) {
	return r.router.Handler
}

func (r *Server) handleAddValidator(ctx *fasthttp.RequestCtx) {
	encryptedSharePrivKey := ctx.PostBody()
	if len(encryptedSharePrivKey) == 0 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		ctx.WriteString("share private key not provided")
		return
	}

	sharePrivateKey, err := r.operatorPrivKey.Decrypt(encryptedSharePrivKey)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusUnauthorized)
		fmt.Fprintf(ctx, "failed to decrypt share: %v", err)
		return
	}

	shareKeystore, shareKeystorePassword, err := keys.GenerateShareKeystore(sharePrivateKey, r.keystorePasswd)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to generate share keystore: %v", err)
		return
	}

	err = r.web3Signer.ImportKeystore(shareKeystore, shareKeystorePassword)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to import share to Web3Signer: %v", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (r *Server) handleRemoveValidator(ctx *fasthttp.RequestCtx) {
	sharePublicKey := ctx.PostBody()
	if len(sharePublicKey) != 48 {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid share public key length, expected 48, got %v", len(sharePublicKey))
		return
	}

	if err := r.web3Signer.DeleteKeystore(sharePublicKey); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to remove share from Web3Signer: %v", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
}

func (r *Server) handleSignValidator(ctx *fasthttp.RequestCtx) {
	var req web3signer.SignRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid request body: %v", err)
		return
	}

	sharePubKeyHex, ok := ctx.UserValue("identifier").(string)
	if !ok {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid share public key")
		return
	}

	sharePubKey, err := hex.DecodeString(strings.TrimPrefix(sharePubKeyHex, "0x"))
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "malformed share public key")
		return
	}

	sig, err := r.web3Signer.Sign(sharePubKey, req)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to sign with Web3Signer: %v", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(sig)
}

func (r *Server) handleOperatorIdentity(ctx *fasthttp.RequestCtx) {
	pubKeyB64, err := r.operatorPrivKey.Public().Base64()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to get public key base64: %v", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(pubKeyB64)
}

func (r *Server) handleSignOperator(ctx *fasthttp.RequestCtx) {
	payload := ctx.PostBody()

	signature, err := r.operatorPrivKey.Sign(payload)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to sign message: %v", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.Write(signature)
}
