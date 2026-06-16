import { createHash } from "node:crypto";

import { lengthPrefixedUtf8 } from "./encoding.js";

// RFC 6962 section 2.1. Domain separation bytes for the Merkle hashing.
// Leaf hashes prefix the leaf bytes with 0x00; internal node hashes
// prefix the concatenation of two child hashes with 0x01. The prefix
// prevents a leaf hash from masquerading as an internal-node hash and
// vice versa.
const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export const MERKLE_LEAF_PREFIX = 0x00;
export const MERKLE_NODE_PREFIX = 0x01;

export const BATCH_DOMAIN = "SEQUESIGN_WITNESS_LOG_BATCH_V0";

function sha256(input: Buffer): Buffer {
  return createHash("sha256").update(input).digest();
}

export function hexToBytes(hex: string): Buffer {
  return Buffer.from(hex, "hex");
}

export function bytesToHex(buf: Buffer): string {
  return buf.toString("hex");
}

// RFC 6962 leaf hash: SHA-256(0x00 || entry_hash_bytes).
export function merkleLeafHash(leafBytes: Buffer): Buffer {
  return sha256(Buffer.concat([LEAF_PREFIX, leafBytes]));
}

// RFC 6962 internal node hash: SHA-256(0x01 || left || right).
export function merkleNodeHash(left: Buffer, right: Buffer): Buffer {
  return sha256(Buffer.concat([NODE_PREFIX, left, right]));
}

// Compute the Merkle root over an ordered list of leaf hashes
// (the raw entry_hash bytes; this function applies the leaf prefix).
// Follows RFC 6962 section 2.1: unbalanced trees split at the largest
// power of two strictly less than the leaf count, recursing on the
// left and right halves.
export function computeMerkleRoot(leafHashes: Buffer[]): Buffer {
  if (leafHashes.length === 0) {
    throw new Error("computeMerkleRoot requires at least one leaf");
  }
  return treeHash(leafHashes.map(merkleLeafHash));
}

function treeHash(level: Buffer[]): Buffer {
  if (level.length === 1) return level[0];
  const split = largestPowerOfTwoLessThan(level.length);
  const left = treeHash(level.slice(0, split));
  const right = treeHash(level.slice(split));
  return merkleNodeHash(left, right);
}

// Largest power of two strictly less than n. RFC 6962 section 2.1.
function largestPowerOfTwoLessThan(n: number): number {
  if (n < 2) throw new Error("largestPowerOfTwoLessThan requires n >= 2");
  let p = 1;
  while (p * 2 < n) p *= 2;
  return p;
}

// RFC 6962 section 2.1.1 audit path: ordered list of sibling hashes
// from leaf to root. Returns [] for a tree of size 1.
export function buildAuditPath(leafHashes: Buffer[], leafIndex: number): Buffer[] {
  if (leafIndex < 0 || leafIndex >= leafHashes.length) {
    throw new Error(
      `buildAuditPath: leafIndex ${leafIndex} out of range for tree size ${leafHashes.length}`
    );
  }
  const level = leafHashes.map(merkleLeafHash);
  return collectPath(level, leafIndex);
}

function collectPath(level: Buffer[], index: number): Buffer[] {
  if (level.length === 1) return [];
  const split = largestPowerOfTwoLessThan(level.length);
  if (index < split) {
    const right = treeHash(level.slice(split));
    return [...collectPath(level.slice(0, split), index), right];
  }
  const left = treeHash(level.slice(0, split));
  return [...collectPath(level.slice(split), index - split), left];
}

// Verify an RFC 6962 audit path. The path is ordered leaf-first (see
// buildAuditPath): the first sibling is the leaf's immediate neighbor
// at the lowest level, the last sibling is the root's other child.
// We collect the side bits top-down, then reverse them so the bottom
// bit matches auditPath[0], and walk back up applying each sibling.
export function verifyAuditPath(args: {
  leafHash: Buffer;
  leafIndex: number;
  treeSize: number;
  auditPath: Buffer[];
  expectedRoot: Buffer;
}): boolean {
  if (args.leafIndex < 0 || args.leafIndex >= args.treeSize) return false;
  const sides: ("left" | "right")[] = [];
  let index = args.leafIndex;
  let size = args.treeSize;
  while (size > 1) {
    const split = largestPowerOfTwoLessThan(size);
    if (index < split) {
      sides.push("left");
      size = split;
    } else {
      sides.push("right");
      index -= split;
      size -= split;
    }
  }
  if (sides.length !== args.auditPath.length) return false;
  sides.reverse();
  let hash = merkleLeafHash(args.leafHash);
  for (let i = 0; i < sides.length; i++) {
    if (sides[i] === "left") {
      // leaf's subtree is on the left at this level; sibling is to its right.
      hash = merkleNodeHash(hash, args.auditPath[i]);
    } else {
      // leaf's subtree is on the right; sibling is to its left.
      hash = merkleNodeHash(args.auditPath[i], hash);
    }
  }
  if (hash.length !== args.expectedRoot.length) return false;
  for (let i = 0; i < hash.length; i++) {
    if (hash[i] !== args.expectedRoot[i]) return false;
  }
  return true;
}

// 8-byte big-endian encoding of a non-negative integer.
function uint64BE(value: number | bigint): Buffer {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(value), 0);
  return buf;
}

// Canonical signing message for a sealed batch. The witness signs this
// to commit to the batch's root and its position in the log. Mixed
// encoding: length-prefixed UTF-8 strings for variable-length text,
// 8-byte big-endian for the integer positions, and the raw 32-byte
// Merkle root.
export function batchSigningMessage(args: {
  logId: string;
  batchId: number | bigint;
  treeSize: number | bigint;
  firstPosition: number | bigint;
  lastPosition: number | bigint;
  batchSealedAt: string;
  merkleRootHex: string;
}): Buffer {
  const rootBytes = hexToBytes(args.merkleRootHex);
  if (rootBytes.length !== 32) {
    throw new Error(
      `batchSigningMessage: merkle_root must be 32 bytes (64 hex), got ${rootBytes.length} bytes`
    );
  }
  return Buffer.concat([
    lengthPrefixedUtf8([BATCH_DOMAIN, args.logId]),
    uint64BE(args.batchId),
    uint64BE(args.treeSize),
    uint64BE(args.firstPosition),
    uint64BE(args.lastPosition),
    lengthPrefixedUtf8([args.batchSealedAt]),
    rootBytes
  ]);
}
