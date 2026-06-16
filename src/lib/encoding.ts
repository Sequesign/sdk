export function lengthPrefixedUtf8(fields: string[]): Buffer {
  const chunks: Buffer[] = [];
  for (const field of fields) {
    const bytes = Buffer.from(field, "utf8");
    const len = Buffer.alloc(4);
    len.writeUInt32BE(bytes.length, 0);
    chunks.push(len, bytes);
  }
  return Buffer.concat(chunks);
}
