import { randomBytes } from "node:crypto";

function shortId(): string {
  return randomBytes(8).toString("hex");
}

export function generateChainId(): string {
  return `chn_${shortId()}`;
}

export function generateReceiptId(): string {
  return `rec_${shortId()}`;
}

export function generateActionId(sequence: number, actionType: string): string {
  const padded = String(sequence).padStart(3, "0");
  return `act_${padded}_${actionType}`;
}

export function generateApprovalId(): string {
  return `appr_${shortId()}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}
