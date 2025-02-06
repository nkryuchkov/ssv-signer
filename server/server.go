package server

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/fasthttp/router"
	"github.com/ssvlabs/ssv-signer/keystore"
	"github.com/ssvlabs/ssv-signer/web3signer"
	spectypes "github.com/ssvlabs/ssv-spec/types"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

type Server struct {
	Logger           *zap.Logger
	OperatorKeystore *keystore.OperatorKeyStore
	Web3SignerClient web3signer.Interface
	Router           *router.Router
}

func New(logger *zap.Logger, operatorKeyStore *keystore.OperatorKeyStore, web3SignerClient web3signer.Interface) *Server {
	r := router.New()

	server := &Server{
		Logger:           logger,
		OperatorKeystore: operatorKeyStore,
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
	EncryptedShare     string `json:"encrypted_share"`
	ValidatorPublicKey string `json:"validator_pubkey"`
}

type AddValidatorResponse struct{}

func (r *Server) handleAddValidator(ctx *fasthttp.RequestCtx) {
	var req AddValidatorRequest
	if err := json.Unmarshal(ctx.PostBody(), &req); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid request body: %v", err)
		return
	}

	encryptedShare, err := hex.DecodeString(req.EncryptedShare)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "invalid validator public key: %v", err)
		return
	}

	decryptedShare, err := r.OperatorKeystore.PrivKey.Decrypt(encryptedShare)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "failed to decrypt share: %v", err)
		return
	}

	share := &spectypes.Share{} // TODO: or ssvtypes.Share?
	if err := share.Decode(decryptedShare); err != nil {
		ctx.SetStatusCode(fasthttp.StatusBadRequest)
		fmt.Fprintf(ctx, "failed to decode decrypted share: %v", err)
		return
	}

	shareKeyStore, shareKeyStorePassword, err := r.OperatorKeystore.GenerateShareKeystore(share.SharePubKey)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to generate share keystore: %v", err)
		return
	}

	err = r.Web3SignerClient.ImportKeystore(shareKeyStore, shareKeyStorePassword)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to import share to Web3Signer: %v", err)
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
		fmt.Fprintf(ctx, "invalid request body: %v", err)
		return
	}

	if err := r.Web3SignerClient.DeleteKeystore(req.SharePublicKey); err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to remove share from Web3Signer: %v", err)
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
		fmt.Fprintf(ctx, "invalid request body: %v", err)
		return
	}

	sig, err := r.Web3SignerClient.Sign(req.SharePublicKey, req.Payload)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to sign with Web3Signer: %v", err)
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
	pubKeyB64, err := r.OperatorKeystore.PrivKey.Public().Base64()
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to get public key base64: %v", err)
		return
	}

	resp := OperatorIdentityResponse{
		PublicKey: string(pubKeyB64),
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
		fmt.Fprintf(ctx, "invalid request body: %v", err)
		return
	}

	signature, err := r.OperatorKeystore.PrivKey.Sign(req.Payload)
	if err != nil {
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		fmt.Fprintf(ctx, "failed to sign message: %v", err)
		return
	}

	ctx.SetContentType("application/json")
	ctx.SetStatusCode(fasthttp.StatusOK)
	_ = json.NewEncoder(ctx).Encode(OperatorSignResponse{Signature: signature})
}
