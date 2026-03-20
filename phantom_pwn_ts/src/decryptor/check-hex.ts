export function checkForHexBytes(line: Buffer): {
  decoded: Buffer;
  hexContent: Buffer;
  errorDetected: number;
} {
  const hexPrefix = Buffer.from("$HEX[");
  const suffix = 0x5d; // ']'

  if (line.subarray(0, hexPrefix.length).equals(hexPrefix)) {
    let errorDetected = 0;
    let buf = Buffer.from(line);

    if (buf[buf.length - 1] !== suffix) {
      buf = Buffer.concat([buf, Buffer.from("]")]);
      errorDetected = 1;
    }

    const startIdx = buf.indexOf(0x5b); // '['
    const endIdx = buf.lastIndexOf(suffix);

    if (startIdx === -1 || endIdx === -1 || endIdx <= startIdx) {
      return { decoded: line, hexContent: line, errorDetected: 1 };
    }

    const hexContent = buf.subarray(startIdx + 1, endIdx);

    try {
      const decoded = Buffer.from(hexContent.toString("ascii"), "hex");
      return { decoded, hexContent, errorDetected };
    } catch {
      // Clean invalid hex characters
      const cleaned = hexContent
        .toString("ascii")
        .replace(/[^0-9a-fA-F]/g, "");
      const padded = cleaned.length % 2 !== 0 ? "0" + cleaned : cleaned;

      try {
        const decoded = Buffer.from(padded, "hex");
        return { decoded, hexContent, errorDetected: 1 };
      } catch {
        return { decoded: line, hexContent: line, errorDetected: 1 };
      }
    }
  }

  return { decoded: line, hexContent: line, errorDetected: 0 };
}
