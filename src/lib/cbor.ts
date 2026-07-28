// Minimal, dependency-free, deterministic CBOR (RFC 8949) — just the subset
// COSE Sign1 (RFC 9052) needs: unsigned/negative integers, byte strings, text
// strings, arrays, maps, null, and booleans. Hand-rolled for the same reason
// JCS (canonicalize.ts), the RFC 6962 Merkle tree (merkle.ts), and the JSON
// Schema validator (schema-validation.ts) are hand-rolled: an independent
// verifier in any language should be a weekend port, not a "pull in a CBOR
// library" project (docs/protocol-spec.md section 2.7). We deliberately do NOT
// support floats, tags, indefinite-length items, or bignums — a COSE Sign1 over
// an Ed25519 (EdDSA) key never needs them, and refusing them keeps the encoder
// canonical and the decoder's attack surface tiny.
//
// Determinism follows RFC 8949 section 4.2.1 "Core Deterministic Encoding":
// integers use the shortest form, definite lengths only, and map keys are
// sorted by their encoded bytes (length-first, then bytewise lexicographic).
// Two equal values therefore always encode to identical bytes, which is what
// makes a signature over CBOR reproducible.

// Major types (high 3 bits of the initial byte).
const MT_UINT = 0;
const MT_NEGINT = 1;
const MT_BSTR = 2;
const MT_TSTR = 3;
const MT_ARRAY = 4;
const MT_MAP = 5;
const MT_SIMPLE = 7; // simple values / floats; we only use false/true/null.

// A CBOR value in the supported subset. Maps use a JS Map so integer keys
// (which COSE headers require — alg is label 1, kid is label 4) survive
// round-trips; a plain object would coerce them to strings.
export type CborValue = number | boolean | null | Uint8Array | string | CborValue[] | CborMap;
export type CborMap = Map<CborKey, CborValue>;
export type CborKey = number | string;

function assertSafeInteger(n: number): void {
  if (!Number.isInteger(n)) throw new Error(`cbor: only integers are supported, got ${n}`);
  if (!Number.isSafeInteger(n))
    throw new Error(`cbor: integer ${n} exceeds the safe range this encoder supports`);
}

// Encode a major type + argument (length or value) in the shortest form.
function encodeHead(major: number, argument: number): Uint8Array {
  const mt = major << 5;
  if (argument < 24) return Uint8Array.of(mt | argument);
  if (argument < 0x100) return Uint8Array.of(mt | 24, argument);
  if (argument < 0x10000) return Uint8Array.of(mt | 25, argument >> 8, argument & 0xff);
  if (argument < 0x100000000)
    return Uint8Array.of(
      mt | 26,
      (argument >>> 24) & 0xff,
      (argument >>> 16) & 0xff,
      (argument >>> 8) & 0xff,
      argument & 0xff
    );
  // 64-bit length. JS bitwise ops are 32-bit, so split into hi/lo halves.
  const hi = Math.floor(argument / 0x100000000);
  const lo = argument >>> 0;
  return Uint8Array.of(
    mt | 27,
    (hi >>> 24) & 0xff,
    (hi >>> 16) & 0xff,
    (hi >>> 8) & 0xff,
    hi & 0xff,
    (lo >>> 24) & 0xff,
    (lo >>> 16) & 0xff,
    (lo >>> 8) & 0xff,
    lo & 0xff
  );
}

function concat(chunks: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function encodeValue(value: CborValue): Uint8Array {
  if (value === null) return Uint8Array.of((MT_SIMPLE << 5) | 22); // 0xf6
  if (value === false) return Uint8Array.of((MT_SIMPLE << 5) | 20); // 0xf4
  if (value === true) return Uint8Array.of((MT_SIMPLE << 5) | 21); // 0xf5
  if (typeof value === "number") {
    assertSafeInteger(value);
    return value >= 0 ? encodeHead(MT_UINT, value) : encodeHead(MT_NEGINT, -value - 1); // -1 - n encodes n.
  }
  if (typeof value === "string") {
    const bytes = new TextEncoder().encode(value);
    return concat([encodeHead(MT_TSTR, bytes.length), bytes]);
  }
  if (value instanceof Uint8Array) {
    return concat([encodeHead(MT_BSTR, value.length), value]);
  }
  if (Array.isArray(value)) {
    return concat([encodeHead(MT_ARRAY, value.length), ...value.map(encodeValue)]);
  }
  if (value instanceof Map) {
    // Deterministic map: encode each key, sort entries by encoded-key bytes
    // (length-first, then lexicographic), then emit. Duplicate keys are a
    // programming error (a Map cannot hold them, but a caller could pass a
    // number and its string twin, e.g. 4 and "4"); their encodings differ, so
    // they are treated as distinct keys, which matches CBOR semantics.
    const entries = [...value.entries()].map(([k, v]) => ({
      keyBytes: encodeValue(typeof k === "number" ? k : String(k)),
      valueBytes: encodeValue(v)
    }));
    entries.sort((a, b) => compareBytes(a.keyBytes, b.keyBytes));
    return concat([
      encodeHead(MT_MAP, entries.length),
      ...entries.flatMap((e) => [e.keyBytes, e.valueBytes])
    ]);
  }
  throw new Error(`cbor: unsupported value of type ${typeof value}`);
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  if (a.length !== b.length) return a.length - b.length;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return 0;
}

export function encodeCbor(value: CborValue): Uint8Array {
  return encodeValue(value);
}

// --- Decoder -------------------------------------------------------------
// A strict decoder for the same subset. It rejects anything outside it
// (floats, tags, indefinite lengths, unsupported simple values) rather than
// skipping — a verifier must not silently accept an item it cannot model. It
// also rejects trailing bytes after the top-level item, so a COSE Sign1 blob
// with junk appended does not verify.

class Reader {
  constructor(
    private readonly buf: Uint8Array,
    private pos = 0
  ) {}
  private need(n: number): void {
    if (this.pos + n > this.buf.length) throw new Error("cbor: unexpected end of input");
  }
  readByte(): number {
    this.need(1);
    return this.buf[this.pos++];
  }
  readBytes(n: number): Uint8Array {
    this.need(n);
    const out = this.buf.slice(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
  atEnd(): boolean {
    return this.pos === this.buf.length;
  }
}

function readArgument(reader: Reader, info: number): number {
  if (info < 24) return info;
  if (info === 24) return reader.readByte();
  if (info === 25) {
    const b = reader.readBytes(2);
    return (b[0] << 8) | b[1];
  }
  if (info === 26) {
    const b = reader.readBytes(4);
    return b[0] * 0x1000000 + ((b[1] << 16) | (b[2] << 8) | b[3]);
  }
  if (info === 27) {
    const b = reader.readBytes(8);
    const hi = b[0] * 0x1000000 + ((b[1] << 16) | (b[2] << 8) | b[3]);
    const lo = b[4] * 0x1000000 + ((b[5] << 16) | (b[6] << 8) | b[7]);
    const value = hi * 0x100000000 + lo;
    if (!Number.isSafeInteger(value))
      throw new Error("cbor: 64-bit value exceeds the safe integer range");
    return value;
  }
  // info 28-30 are reserved; 31 is indefinite length, which we reject.
  throw new Error(`cbor: unsupported additional-information value ${info}`);
}

function readValue(reader: Reader): CborValue {
  const initial = reader.readByte();
  const major = initial >> 5;
  const info = initial & 0x1f;
  switch (major) {
    case MT_UINT:
      return readArgument(reader, info);
    case MT_NEGINT:
      return -1 - readArgument(reader, info);
    case MT_BSTR:
      return reader.readBytes(readArgument(reader, info));
    case MT_TSTR: {
      const bytes = reader.readBytes(readArgument(reader, info));
      return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    }
    case MT_ARRAY: {
      const len = readArgument(reader, info);
      const out: CborValue[] = [];
      for (let i = 0; i < len; i++) out.push(readValue(reader));
      return out;
    }
    case MT_MAP: {
      const len = readArgument(reader, info);
      const out: CborMap = new Map();
      for (let i = 0; i < len; i++) {
        const key = readValue(reader);
        if (typeof key !== "number" && typeof key !== "string")
          throw new Error("cbor: only integer or text map keys are supported");
        if (out.has(key)) throw new Error("cbor: duplicate map key");
        out.set(key, readValue(reader));
      }
      return out;
    }
    case MT_SIMPLE: {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      throw new Error(`cbor: unsupported simple/float value (additional info ${info})`);
    }
    default:
      throw new Error(`cbor: unsupported major type ${major}`);
  }
}

// Decode a single top-level CBOR item. Throws if the bytes are malformed, use
// an unsupported feature, or carry trailing data past the first item.
export function decodeCbor(bytes: Uint8Array): CborValue {
  const reader = new Reader(bytes);
  const value = readValue(reader);
  if (!reader.atEnd()) throw new Error("cbor: unexpected trailing bytes after top-level item");
  return value;
}
