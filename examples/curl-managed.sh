#!/usr/bin/env bash
#
# curl-managed — drive MANAGED mode with the `sequesign` CLI + curl, no SDK.
#
# Flow: sign locally with the helper, POST the request body to the broker
# (which has the witness co-sign), then assemble + POST the finalize body. The
# broker stores the receipt and returns its URL. Any language can run this same
# flow over plain HTTP.
#
# Prerequisites: bash, curl, jq, openssl, and the agent key your API key is
# registered to.
#   SEQUESIGN_API_KEY                 a write-class API key
#   SEQUESIGN_AGENT_PRIVATE_KEY_PATH  path to the registered agent Ed25519 PEM
#   SEQUESIGN_BROKER_URL              optional (default https://broker.sequesign.com)
#
# Run (after `npm run build`):
#   bash examples/curl-managed.sh
set -euo pipefail

: "${SEQUESIGN_API_KEY:?set SEQUESIGN_API_KEY to a write-class API key}"
KEY="${SEQUESIGN_AGENT_PRIVATE_KEY_PATH:?set SEQUESIGN_AGENT_PRIVATE_KEY_PATH to the registered agent key PEM}"
BROKER="${SEQUESIGN_BROKER_URL:-https://broker.sequesign.com}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SEQUESIGN=(node "$ROOT/dist/sdk/cli.js")   # after `npm run build`; or use: npx sequesign

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CHAIN="chn_$(date +%s)$RANDOM"
RECEIPT="rec_$(date +%s)$RANDOM"
NOW="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
PUBKEY="$(openssl pkey -in "$KEY" -pubout)"

echo "[1] sign the action locally (no network)"
jq -n --arg chain "$CHAIN" --arg receipt "$RECEIPT" --arg pk "$PUBKEY" \
  '{chain_id:$chain, receipt_id:$receipt, sequence:1,
    agent_id:"curl-managed-agent", agent_public_key_pem:$pk,
    task_id:"task_curl_managed", delegator_id:"curl-operator",
    action_type:"policy_checked", evidence:{decision:"approved", amount_usd:100}}' \
  > "$WORK/request.json"
"${SEQUESIGN[@]}" sign --key "$KEY" < "$WORK/request.json" > "$WORK/signed.json"

echo "[2] POST request_body to the broker; the witness co-signs"
jq -c .request_body "$WORK/signed.json" \
  | curl -fsS -X POST "$BROKER/v1/receipt" \
      -H "authorization: Bearer $SEQUESIGN_API_KEY" -H 'content-type: application/json' \
      -d @- > "$WORK/receipt.json"

echo "[3] assemble the finalize body from the signed action + the witness attestation"
jq -cn --slurpfile s "$WORK/signed.json" --slurpfile r "$WORK/receipt.json" \
  '{action_record:$s[0].action_record, evidence_blob:$s[0].evidence_blob,
    agent_attestation:$s[0].agent_attestation, witness_attestation:$r[0].witness_attestation}' \
  > "$WORK/actions.ndjson"
jq -n --arg chain "$CHAIN" --arg receipt "$RECEIPT" --arg pk "$PUBKEY" --arg now "$NOW" \
  '{chain_id:$chain, receipt_id:$receipt, receipt_mode:"freeform",
    agent:{agent_id:"curl-managed-agent", agent_public_key:$pk},
    task:{task_id:"task_curl_managed", delegator_id:"curl-operator", delegated_at:$now},
    evidence_custody:"both", envelope_custody:"both"}' \
  > "$WORK/session.json"
"${SEQUESIGN[@]}" assemble-finalize --session "$WORK/session.json" --actions "$WORK/actions.ndjson" \
  > "$WORK/finalize.json"

echo "[4] POST the finalize body; the broker stores the receipt"
curl -fsS -X POST "$BROKER/v1/receipts/finalize" \
  -H "authorization: Bearer $SEQUESIGN_API_KEY" -H 'content-type: application/json' \
  -d @"$WORK/finalize.json" | jq '{receipt_id, receipt_url}'

echo "DONE — managed receipt recorded via curl. Open it at https://verify.sequesign.com"
