// Chain genesis (initial_chain_state) construction.
//
// The genesis is the seed of the hash chain. Two constructions exist:
//
//   V0 (legacy / unparameterized): H(lp["SEQUESIGN_INITIAL_STATE_V0", chainId])
//     Used by freeform, schema-only, and profile sessions that bind no
//     parameters. Commits to nothing but the chain id — unchanged from the
//     original protocol, so those receipts stay byte-identical.
//
//   V1 (parameterized mandate, template system Phase 2):
//     H(lp["SEQUESIGN_GENESIS_V1", chainId, taskId, delegatorId, agentId,
//         profile_hash, params_hash])
//     Used only when a session binds parameters. It commits the mandate
//     (profile_hash + params_hash) and the parties into the chain root, so a
//     swapped mandate or tampered parameters break the recomputed genesis and
//     therefore the whole chain. The verifier RECOMPUTES this from the
//     receipt's own fields and rejects a mismatch — that recompute is what
//     gives the binding teeth.
//
// WIRE CONTRACT (docs/protocol-spec.md section 2.8): this is the single source
// of truth shared by the SDK (sealer) and the offline verifier. The field
// order and domain-separation tag are frozen; changing either changes every
// V1 genesis and requires a new tag.

import { sha256Hex } from "./hash.js";
import { lengthPrefixedUtf8 } from "./encoding.js";

export const GENESIS_V0_TAG = "SEQUESIGN_INITIAL_STATE_V0";
export const GENESIS_V1_TAG = "SEQUESIGN_GENESIS_V1";

export function computeGenesisV0(chainId: string): string {
  return sha256Hex(lengthPrefixedUtf8([GENESIS_V0_TAG, chainId]));
}

export type GenesisV1Inputs = {
  chainId: string;
  taskId: string;
  delegatorId: string;
  agentId: string;
  profileHash: string;
  paramsHash: string;
};

export function computeGenesisV1(input: GenesisV1Inputs): string {
  return sha256Hex(
    lengthPrefixedUtf8([
      GENESIS_V1_TAG,
      input.chainId,
      input.taskId,
      input.delegatorId,
      input.agentId,
      input.profileHash,
      input.paramsHash
    ])
  );
}
