import { createReadStream, createWriteStream, readFileSync } from "fs";
import { createInterface } from "readline";
import { Vault, decryptVault, isValid } from "./vault.js";
import { checkForHexBytes } from "./check-hex.js";
import { isAllVaultsCracked } from "./utils.js";

export async function startProc(
  wordlistFile: string,
  outputPath: string,
  _numThreads: number,
  vaults: Vault[],
  state: { crackedCount: number; linesProcessed: number },
  abortController: AbortController
): Promise<void> {
  const inputStream = wordlistFile
    ? createReadStream(wordlistFile)
    : process.stdin;

  const outputStream = outputPath
    ? createWriteStream(outputPath, { flags: "a" })
    : process.stdout;

  const rl = createInterface({
    input: inputStream,
    crlfDelay: Infinity,
  });

  for await (const line of rl) {
    if (abortController.signal.aborted) break;

    processPassword(
      Buffer.from(line),
      vaults,
      outputStream,
      state,
      abortController
    );
  }

  if (outputPath && outputStream !== process.stdout) {
    (outputStream as ReturnType<typeof createWriteStream>).end();
  }

  console.error("Finished");
}

function processPassword(
  password: Buffer,
  vaults: Vault[],
  writer: NodeJS.WritableStream,
  state: { crackedCount: number; linesProcessed: number },
  abortController: AbortController
): void {
  state.linesProcessed++;

  const { decoded } = checkForHexBytes(password);

  for (const vault of vaults) {
    if (vault.decrypted) continue;

    const decryptedData = decryptVault(
      vault.encryptedData,
      new Uint8Array(decoded),
      vault.salt,
      vault.nonce,
      vault.iterations,
      vault.kdf
    );

    if (!decryptedData || !isValid(decryptedData)) continue;

    vault.decrypted = true;
    state.crackedCount++;
    const output = `${vault.vaultText}:${decoded.toString()}\n`;
    writer.write(output);

    if (isAllVaultsCracked(vaults)) {
      abortController.abort();
    }
    return;
  }
}
