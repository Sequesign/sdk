// Canonical JSON serialization, conformant to RFC 8785 (JSON
// Canonicalization Scheme, JCS). Sequesign hashes and signs over the
// output of this function, so its byte output is a wire-format
// commitment. See docs/protocol-spec.md section 2.5.
//
// Two input-handling points, both consistent with RFC 8785 (which
// operates on JSON, a data model with neither undefined nor non-finite
// numbers):
//   - undefined object values are dropped before serialization (JSON
//     has no undefined; JCS does not speak to it).
//   - NaN, Infinity, and -Infinity are rejected with an error (JCS
//     forbids non-finite numbers).
export function canonicalize(value: unknown): string {
  return serialize(value);
}

// Matches a lone (unpaired) UTF-16 surrogate: a high surrogate not
// followed by a low surrogate, or a low surrogate not preceded by a high
// surrogate. RFC 8785 requires well-formed Unicode, so a string carrying
// a lone surrogate is rejected rather than serialized.
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

// RFC 8785 requires well-formed Unicode for both string values and
// property names. Reject a lone surrogate in either rather than letting
// JSON.stringify silently emit it.
function assertWellFormedUnicode(s: string, what: string): void {
  if (LONE_SURROGATE.test(s)) {
    throw new Error(
      `Unsupported value in canonical JSON: ${what} contains a lone surrogate (RFC 8785 requires well-formed Unicode)`
    );
  }
}

function serialize(value: unknown): string {
  if (value === null) return "null";

  const valueType = typeof value;

  if (valueType === "boolean") return value ? "true" : "false";

  if (valueType === "number") {
    const n = value as number;
    if (!Number.isFinite(n)) {
      throw new Error(
        `Unsupported value in canonical JSON: ${String(n)} (RFC 8785 forbids NaN and Infinity)`
      );
    }
    // ECMA-262 Number-to-String shortest round-trip, which is exactly
    // the number serialization RFC 8785 section 3.2.2.3 specifies.
    return JSON.stringify(n);
  }

  if (valueType === "string") {
    const s = value as string;
    assertWellFormedUnicode(s, "string");
    // RFC 8785 section 3.2.2.2 string escaping. JSON.stringify of a
    // standalone string produces the same escaping (short escapes for
    // the named control characters, \u00xx for the rest, raw output for
    // everything at or above U+0020 except the quote and backslash, and
    // no escaping of the forward slash).
    return JSON.stringify(s);
  }

  if (Array.isArray(value)) {
    // JSON has no array holes. JSON.stringify would coerce a hole to
    // null, silently signing a value the caller did not write, so reject
    // a sparse array instead. An explicit undefined element falls through
    // to serialize(undefined) below and is rejected as an unsupported
    // value, matching the object-value handling.
    const items: string[] = [];
    for (let i = 0; i < value.length; i++) {
      if (!(i in value)) {
        throw new Error(
          `Unsupported value in canonical JSON: sparse array hole at index ${i} (JSON has no array holes)`
        );
      }
      items.push(serialize(value[i]));
    }
    return "[" + items.join(",") + "]";
  }

  if (valueType === "object") {
    const input = value as Record<string, unknown>;
    // RFC 8785 section 3.2.3: sort property names by their UTF-16 code
    // units. The default Array sort comparator compares strings by
    // UTF-16 code unit, which is that ordering. We then build the JSON
    // text ourselves, in that order, rather than handing the sorted
    // object to JSON.stringify: V8 enumerates integer-index keys (for
    // example "10", "2") in ascending numeric order regardless of
    // insertion order, which would silently undo the code-unit sort.
    const keys = Object.keys(input).sort();
    const members: string[] = [];
    for (const key of keys) {
      const item = input[key];
      if (item === undefined) continue;
      // Property names are serialized as JSON strings too; hold them to the
      // same well-formed-Unicode requirement as string values (a lone
      // surrogate in a key would otherwise be emitted by JSON.stringify).
      assertWellFormedUnicode(key, "property name");
      members.push(`${JSON.stringify(key)}:${serialize(item)}`);
    }
    return "{" + members.join(",") + "}";
  }

  throw new Error(`Unsupported value in canonical JSON: ${valueType}`);
}
