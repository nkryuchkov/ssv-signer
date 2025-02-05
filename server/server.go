package server

import (
	"encoding/json"
	"fmt"

	"github.com/fasthttp/router"
	"github.com/ssvlabs/ssv-signer/web3signer"
	"github.com/ssvlabs/ssv/operator/keys"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type Server struct {
	Logger           *zap.Logger
	OperatorKey      keys.OperatorPrivateKey
	Web3SignerClient web3signer.Interface
	Router           *router.Router
}

func New(logger *zap.Logger, operatorKey keys.OperatorPrivateKey, web3SignerClient web3signer.Interface) *Server {
	r := router.New()

	server := &Server{
		Logger:           logger,
		OperatorKey:      operatorKey,
		Web3SignerClient: web3SignerClient,
		Router:           r,
	}

	r.POST("/v1/validators/add", server.handleAddValidator)
	r.POST("/v1/validators/remove", server.handleRemoveValidator)
	r.POST("/v1/validators/sign", server.handleSignValidator)

	r.GET("/v1/operator/identity", server.handleOperatorIdentity)
	r.POST("/v1/operator/sign", server.handleSignOperator)

	return server
}

func (r *Server) Handler() func(ctx *fasthttp.RequestCtx) {
	return r.Router.Handler
}

type AddValidatorRequest struct {
	EncryptedShare     []byte `json:"encrypted_share"`
	ValidatorPublicKey string `json:"validator_pubkey"`
}

type AddValidatorResponse struct{}

func (r *Server) handleAddValidator(ctx *fasthttp.RequestCtx) {
	var req struct {
		EncryptedShare     []byte `json:"encrypted_share"`
		ValidatorPublicKey string `json:"validator_pubkey"`
	}
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid request body")
		return
	}

	decryptedShare, err := r.OperatorKey.Decrypt(req.EncryptedShare)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "failed to decrypt share")
		return
	}

	// TODO: web3signer expects keystores and their passwords, not decrypted share
	_ = decryptedShare

	err = r.Web3SignerClient.ImportKeystore()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to import share to Web3Signer")
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(map[string]string{
		"status": "ok",
	})
}

type RemoveValidatorRequest struct {
	SharePublicKey string `json:"share_pubkey"`
}

type RemoveValidatorResponse struct{}

func (r *Server) handleRemoveValidator(ctx *fasthttp.RequestCtx) {
	var req RemoveValidatorRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid request body")
		return
	}

	if err := r.Web3SignerClient.DeleteKeystore(req.SharePublicKey); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to remove share from Web3Signer")
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(RemoveValidatorResponse{})
}

type ValidatorSignRequest struct {
	SharePublicKey string `json:"share_pubkey"`
	Payload        []byte `json:"payload"`
}

type ValidatorSignResponse struct {
	Signature string `json:"signature"`
}

func (r *Server) handleSignValidator(ctx *fasthttp.RequestCtx) {
	var req ValidatorSignRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid request body")
		return
	}

	sig, err := r.Web3SignerClient.Sign(req.SharePublicKey, req.Payload)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to sign with Web3Signer")
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(ValidatorSignResponse{Signature: sig})
}

type OperatorIdentityResponse struct {
	PublicKey string `json:"public_key"`
}

func (r *Server) handleOperatorIdentity(ctx *fasthttp.RequestCtx) {
	resp := OperatorIdentityResponse{
		PublicKey: string(r.OperatorKey.Base64()),
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(resp)
}

type OperatorSignRequest struct {
	Payload []byte `json:"payload"`
}

type OperatorSignResponse struct {
	Signature []byte `json:"signature"`
}

func (r *Server) handleSignOperator(ctx *fasthttp.RequestCtx) {
	var req OperatorSignRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid request body")
		return
	}

	signature, err := r.OperatorKey.Sign(req.Payload)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to sign message")
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(OperatorSignResponse{Signature: signature})
}
