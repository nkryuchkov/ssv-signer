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
	Status  Status `json:"status"`
	Message string `json:"message"`
}

type Status string

type SignRequest struct {
	ForkInfo                    ForkInfo                              `json:"fork_info"`
	SigningRoot                 string                                `json:"signing_root,omitempty"`
	Type                        SignedObjectType                      `json:"type"`
	Attestation                 *phase0.AttestationData               `json:"attestation,omitempty"`
	BeaconBlock                 *BeaconBlockData                      `json:"beacon_block,omitempty"`
	VoluntaryExit               *phase0.VoluntaryExit                 `json:"voluntary_exit,omitempty"`
	AggregateAndProof           *phase0.AggregateAndProof             `json:"aggregate_and_proof,omitempty"`
	AggregationSlot             *AggregationSlotData                  `json:"aggregation_slot,omitempty"`
	RandaoReveal                *RandaoRevealData                     `json:"randao_reveal,omitempty"`
	SyncCommitteeMessage        *SyncCommitteeMessageData             `json:"sync_committee_message,omitempty"`
	SyncAggregatorSelectionData *SyncCommitteeAggregatorSelectionData `json:"sync_aggregator_selection_data,omitempty"`
	ContributionAndProof        *altair.ContributionAndProof          `json:"contribution_and_proof,omitempty"`
	ValidatorRegistration       *v1.ValidatorRegistration             `json:"validator_registration,omitempty"`
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
	AggregationSlot                   SignedObjectType = "AGGREGATION_SLOT"
	AggregateAndProof                 SignedObjectType = "AGGREGATE_AND_PROOF"
	Attestation                       SignedObjectType = "ATTESTATION"
	Block                             SignedObjectType = "BLOCK" // TODO: not tested
	BlockV2                           SignedObjectType = "BLOCK_V2"
	Deposit                           SignedObjectType = "DEPOSIT" // TODO: not tested
	RandaoReveal                      SignedObjectType = "RANDAO_REVEAL"
	VoluntaryExit                     SignedObjectType = "VOLUNTARY_EXIT" // TODO: not tested
	SyncCommitteeMessage              SignedObjectType = "SYNC_COMMITTEE_MESSAGE"
	SyncCommitteeSelectionProof       SignedObjectType = "SYNC_COMMITTEE_SELECTION_PROOF"
	SyncCommitteeContributionAndProof SignedObjectType = "SYNC_COMMITTEE_CONTRIBUTION_AND_PROOF"
	ValidatorRegistration             SignedObjectType = "VALIDATOR_REGISTRATION"
)

type BeaconBlockData struct {
	Version     string                    `json:"version"`
	BlockHeader *phase0.BeaconBlockHeader `json:"block_header"`
}

type AggregationSlotData struct {
	Slot phase0.Slot `json:"slot"`
}

type RandaoRevealData struct {
	Epoch phase0.Epoch `json:"epoch"`
}

type SyncCommitteeMessageData struct {
	BeaconBlockRoot phase0.Root `json:"beacon_block_root"`
	Slot            phase0.Slot `json:"slot"`
}

type SyncCommitteeAggregatorSelectionData struct {
	Slot              phase0.Slot           `json:"slot"`
	SubcommitteeIndex phase0.CommitteeIndex `json:"subcommittee_index"` // phase0.CommitteeIndex type to marshal to string
}
