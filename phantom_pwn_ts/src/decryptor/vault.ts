import { createHash } from "crypto";
import { pbkdf2Sync } from "crypto";
import { scryptSync } from "crypto";
import { readFileSync } from "fs";
import nacl from "tweetnacl";
import bs58 from "bs58";

export interface Vault {
  encryptedData: Uint8Array;
  salt: Uint8Array;
  nonce: Uint8Array;
  iterations: number;
  decrypted: boolean;
  kdf: string;
  vaultText: string;
}

export function isValid(_data: Uint8Array): boolean {
  return true;
}

export function decryptVault(
  encryptedData: Uint8Array,
  password: Uint8Array,
  salt: Uint8Array,
  nonce: Uint8Array,
  iterations: number,
  kdf: string
): Uint8Array | null {
  if (nonce.length !== 24) {
    return null;
  }

  let key: Uint8Array;

  switch (kdf) {
    case "pbkdf2":
      key = new Uint8Array(
        pbkdf2Sync(Buffer.from(password), Buffer.from(salt), iterations, 32, "sha256")
      );
      break;
    case "scrypt": {
      const N = 4096;
      const r = 8;
      const p = 1;
      key = new Uint8Array(
        scryptSync(Buffer.from(password), Buffer.from(salt), 32, { N, r, p })
      );
      break;
    }
    default:
      return null;
  }

  const decrypted = nacl.secretbox.open(encryptedData, nonce, key);
  return decrypted;
}

export function readVaultData(filePath: string): Vault[] {
  const content = readFileSync(filePath, "utf-8");
  const lines = content.split("\n").filter((line) => line.trim().length > 0);
  const vaults: Vault[] = [];

  for (const line of lines) {
    try {
      const hash = JSON.parse(line);
      const ek = hash.encryptedKey;

      if (
        ek?.digest !== "sha256" ||
        (ek?.kdf !== "pbkdf2" && ek?.kdf !== "scrypt") ||
        !ek?.iterations ||
        ek.iterations <= 0 ||
        !ek?.encrypted ||
        !ek?.salt ||
        !ek?.nonce
      ) {
        console.error(`Invalid or incomplete data encountered in JSON: ${line}`);
        continue;
      }

      const encryptedData = bs58.decode(ek.encrypted);
      const salt = bs58.decode(ek.salt);
      const nonce = bs58.decode(ek.nonce);

      if (encryptedData.length === 0 || salt.length === 0 || nonce.length === 0) {
        console.error(`Error decoding base58 data: possibly incorrect format or content: ${line}`);
        continue;
      }

      vaults.push({
        encryptedData: new Uint8Array(encryptedData),
        salt: new Uint8Array(salt),
        nonce: new Uint8Array(nonce),
        iterations: ek.iterations,
        kdf: ek.kdf,
        vaultText: line,
        decrypted: false,
      });
    } catch (err) {
      console.error(`Error parsing JSON: ${err}`);
    }
  }

  return vaults;
}
