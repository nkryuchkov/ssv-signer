package web3signer

import (
	"github.com/attestantio/go-eth2-client/api/v1"
	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/phase0"
)

type ImportKeystoreRequest struct {
	Keystores          []string `json:"keystores"`
	Passwords          []string `json:"passwords"`
	SlashingProtection string   `json:"slashing_protection,omitempty"`
}

type ImportKeystoreResponse struct {
	Data    []KeyManagerResponseData `json:"data"`
	Message string                   `json:"message,omitempty"`
}

type DeleteKeystoreRequest struct {
	Pubkeys []string `json:"pubkeys"`
}

type DeleteKeystoreResponse struct {
	Data               []KeyManagerResponseData `json:"data"`
	SlashingProtection string                   `json:"slashing_protection"`
	Message            string                   `json:"message,omitempty"`
}

type KeyManagerResponseData struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

type SignRequest struct {
	ForkInfo    ForkInfo                `json:"fork_info"`
	SigningRoot string                  `json:"signing_root,omitempty"`
	Type        SignedObjectType        `json:"type"`
	Attestation *phase0.AttestationData `json:"attestation,omitempty"`
	BeaconBlock *struct {
		Version     string                    `json:"version"`
		BlockHeader *phase0.BeaconBlockHeader `json:"block_header"`
	} `json:"beacon_block,omitempty"`
	VoluntaryExit     *phase0.VoluntaryExit     `json:"voluntary_exit,omitempty"`
	AggregateAndProof *phase0.AggregateAndProof `json:"aggregate_and_proof,omitempty"`
	AggregationSlot   *struct {
		Slot phase0.Slot `json:"slot"`
	} `json:"aggregation_slot,omitempty"`
	RandaoReveal *struct {
		Epoch phase0.Epoch `json:"epoch"`
	} `json:"randao_reveal,omitempty"`
	SyncCommitteeMessage *struct {
		BeaconBlockRoot phase0.Root `json:"beacon_block_root"`
		Slot            phase0.Slot `json:"slot"`
	} `json:"sync_committee_message,omitempty"`
	SyncAggregatorSelectionData *struct {
		Slot              phase0.Slot           `json:"slot"`
		SubcommitteeIndex phase0.CommitteeIndex `json:"subcommittee_index"` // phase0.CommitteeIndex type to marshal to string
	} `json:"sync_aggregator_selection_data,omitempty"`
	ContributionAndProof  *altair.ContributionAndProof `json:"contribution_and_proof,omitempty"`
	ValidatorRegistration *v1.ValidatorRegistration    `json:"validator_registration,omitempty"`
}

type ForkInfo struct {
	Fork                  ForkType `json:"fork"`
	GenesisValidatorsRoot string   `json:"genesis_validators_root"`
}

type ForkType struct {
	PreviousVersion string `json:"previous_version,omitempty"`
	CurrentVersion  string `json:"current_version,omitempty"`
	Epoch           uint64 `json:"epoch,omitempty"`
}

type SignedObjectType string

const (
	AggregationSlot                   SignedObjectType = "AGGREGATION_SLOT"                      // ok
	AggregateAndProof                 SignedObjectType = "AGGREGATE_AND_PROOF"                   // ok
	Attestation                       SignedObjectType = "ATTESTATION"                           // ok
	Block                             SignedObjectType = "BLOCK"                                 // not tested
	BlockV2                           SignedObjectType = "BLOCK_V2"                              // ok
	Deposit                           SignedObjectType = "DEPOSIT"                               // not tested
	RandaoReveal                      SignedObjectType = "RANDAO_REVEAL"                         // ok
	VoluntaryExit                     SignedObjectType = "VOLUNTARY_EXIT"                        // not tested
	SyncCommitteeMessage              SignedObjectType = "SYNC_COMMITTEE_MESSAGE"                // failed
	SyncCommitteeSelectionProof       SignedObjectType = "SYNC_COMMITTEE_SELECTION_PROOF"        // failed
	SyncCommitteeContributionAndProof SignedObjectType = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF" // failed
	ValidatorRegistration             SignedObjectType = "VALIDATOR_REGISTRATION"                // ok
)

type SignResponse struct {
	Signature string `json:"signature"`
}
