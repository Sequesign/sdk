#!/usr/bin/env bash
#
# curl-direct — drive DIRECT mode with the `sequesign` CLI + curl, no SDK and no
# broker. The agent signs locally, sends ONLY the commitment hashes to the
# witness, then assembles the receipt package itself.
#
# Flow:
#   sign            canonicalize + sign locally (no network); emits witness_request
#   POST /witness   send witness_request (hashes only) -> witness_attestation
#   assemble-receipt fold signed action + witness attestation into a package
#   verify          offline, with no Sequesign call (see examples/01)
#
# Prerequisites: bash, curl, jq, openssl, and your agent key.
#   SEQUESIGN_API_KEY                 write-class key (the witness requires it)
#   SEQUESIGN_AGENT_PRIVATE_KEY_PATH  path to the agent Ed25519 PEM
#   SEQUESIGN_WITNESS_URL             optional (default https://witness.sequesign.com)
#
# Run (after `npm run build`):
#   bash examples/curl-direct.sh
set -euo pipefail

: "${SEQUESIGN_API_KEY:?set SEQUESIGN_API_KEY (the witness requires a write-class key)}"
KEY="${SEQUESIGN_AGENT_PRIVATE_KEY_PATH:?set SEQUESIGN_AGENT_PRIVATE_KEY_PATH to the agent key PEM}"
WITNESS="${SEQUESIGN_WITNESS_URL:-https://witness.sequesign.com}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEQUESIGN=(node "$ROOT/dist/sdk/cli.js")   # after `npm run build`; or use: npx sequesign

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
OUTDIR="$ROOT/out/curl-direct.sequesign"
CHAIN="chn_$(date +%s)$RANDOM"
RECEIPT="rec_$(date +%s)$RANDOM"
NOW="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
PUBKEY="$(openssl pkey -in "$KEY" -pubout)"

echo "[1] sign locally (no network); the result includes a witness_request"
jq -n --arg chain "$CHAIN" --arg receipt "$RECEIPT" --arg pk "$PUBKEY" \
  '{chain_id:$chain, receipt_id:$receipt, sequence:1,
    agent_id:"curl-direct-agent", agent_public_key_pem:$pk,
    task_id:"task_curl_direct", delegator_id:"curl-operator",
    action_type:"policy_checked", evidence:{decision:"approved", amount_usd:100}}' \
  > "$WORK/request.json"
"${SEQUESIGN[@]}" sign --key "$KEY" < "$WORK/request.json" > "$WORK/signed.json"

echo "[2] POST witness_request (commitment hashes only) to the witness"
jq -c .witness_request "$WORK/signed.json" \
  | curl -fsS -X POST "$WITNESS/witness" \
      -H "authorization: Bearer $SEQUESIGN_API_KEY" -H 'content-type: application/json' \
      -d @- > "$WORK/witness_attestation.json"

echo "[3] assemble the receipt package locally (the agent is the custodian)"
# The /witness response body IS the witness_attestation object.
jq -cn --slurpfile s "$WORK/signed.json" --slurpfile w "$WORK/witness_attestation.json" \
  '{action_record:$s[0].action_record, evidence_blob:$s[0].evidence_blob,
    agent_attestation:$s[0].agent_attestation, witness_attestation:$w[0]}' \
  > "$WORK/actions.ndjson"
jq -n --arg chain "$CHAIN" --arg receipt "$RECEIPT" --arg pk "$PUBKEY" --arg now "$NOW" \
  '{chain_id:$chain, receipt_id:$receipt, receipt_mode:"freeform",
    agent:{agent_id:"curl-direct-agent", agent_public_key:$pk},
    task:{task_id:"task_curl_direct", delegator_id:"curl-operator", delegated_at:$now},
    evidence_custody:"both", envelope_custody:"both"}' \
  > "$WORK/session.json"
"${SEQUESIGN[@]}" assemble-receipt \
  --session "$WORK/session.json" --actions "$WORK/actions.ndjson" --out "$OUTDIR" \
  | jq '{package_dir, receipt_id}'

echo "DONE — direct receipt assembled at: $OUTDIR"
echo "Verify it offline:  npx tsx examples/01-verify-offline.ts $OUTDIR"
echo "Or drag the folder into https://verify.sequesign.com"
