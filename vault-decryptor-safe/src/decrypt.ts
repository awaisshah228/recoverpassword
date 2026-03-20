/**
 * MetaMask Vault Decryptor - Safe CLI Version
 *
 * This script runs 100% locally with NO network calls.
 * It reads your vault data from a file, decrypts it with your password,
 * and prints the mnemonic (seed phrase) to the console.
 *
 * Usage:
 *   node dist/decrypt.js --vault <vault.json> --password <your-password>
 *   node dist/decrypt.js --file <000003.log> --password <your-password>
 *
 * The --vault flag expects a JSON file with { data, iv, salt } fields.
 * The --file flag expects a raw Chrome/Chromium log or ldb file.
 */

import { readFileSync } from "fs";
import { resolve } from "path";
// @ts-ignore - no types available
import passworder from "@metamask/browser-passworder";

// ─── Types ───────────────────────────────────────────────────────────────────

interface Vault {
  data: string;
  iv: string;
  salt: string;
  keyMetadata?: {
    algorithm: string;
    params: { iterations: number };
  };
}

interface KeyringData {
  mnemonic?: string | number[];
  [key: string]: unknown;
}

interface Keyring {
  type: string;
  data: KeyringData;
}

// ─── Vault extraction from raw browser log/ldb files ─────────────────────────

function dedupe(arr: Vault[]): Vault[] {
  const result: Vault[] = [];
  arr?.forEach((x) => {
    if (x == null) return;
    if (
      !result.find(
        (y) =>
          Object.keys(x).length === Object.keys(y).length &&
          Object.entries(x).every(
            ([k, ex]) => y[k as keyof Vault] === ex
          )
      )
    ) {
      result.push(x);
    }
  });
  return result;
}

function extractVaultFromFile(data: string): Vault | null {
  // attempt 1: raw JSON vault
  try {
    return JSON.parse(data);
  } catch {
    // not valid JSON
  }

  // attempt 2: pre-v3 cleartext (unencrypted wallet)
  {
    const matches = data.match(/{"wallet-seed":"([^"}]*)"}/);
    if (matches?.length) {
      const mnemonic = matches[1].replace(/\\n*/, "");
      console.log("\n⚠️  WARNING: This vault is UNENCRYPTED (pre-v3 format).");
      console.log(`\nMnemonic: ${mnemonic}\n`);
      process.exit(0);
    }
  }

  // attempt 3: chromium 000003.log on linux
  {
    const matches = data.match(
      /"KeyringController":{"vault":"{[^{}]*}"/
    );
    if (matches?.length) {
      const vaultBody = matches[0].substring(29);
      return JSON.parse(JSON.parse(vaultBody));
    }
  }

  // attempt 4: chromium 000006.log on macOS
  {
    const matches = data.match(
      /KeyringController":(\{"vault":".*?=\\"\}"\})/
    );
    if (matches?.length) {
      try {
        const fragment = matches[1];
        const dataRegex = /\\"data\\":\\"([A-Za-z0-9+\/]*=*)/u;
        const ivRegex = /,\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)/u;
        const saltRegex = /,\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\"/;
        const keyMetaRegex = /,\\"keyMetadata\\":(.*}})/;

        const parts = [dataRegex, ivRegex, saltRegex, keyMetaRegex]
          .map((reg) => fragment.match(reg))
          .map((match) => match![1]);

        return {
          data: parts[0],
          iv: parts[1],
          salt: parts[2],
          keyMetadata: JSON.parse(parts[3].replaceAll("\\", "")),
        };
      } catch {
        // continue
      }
    }
  }

  // attempt 5: chromium 000056.log on macOS (with keyringsMetadata)
  {
    const matches = data.match(
      /"KeyringController":(\{.*?"vault":".*?=\\"\}"\})/
    );
    if (matches?.length) {
      try {
        const fragment = matches[1];
        const dataRegex = /\\"data\\":\\"([A-Za-z0-9+\/]*=*)/u;
        const ivRegex = /,\\"iv\\":\\"([A-Za-z0-9+\/]{10,40}=*)/u;
        const saltRegex = /,\\"salt\\":\\"([A-Za-z0-9+\/]{10,100}=*)\\"/;
        const keyMetaRegex = /,\\"keyMetadata\\":(.*}})/;

        const parts = [dataRegex, ivRegex, saltRegex, keyMetaRegex]
          .map((reg) => fragment.match(reg))
          .map((match) => match![1]);

        return {
          data: parts[0],
          iv: parts[1],
          salt: parts[2],
          keyMetadata: JSON.parse(parts[3].replaceAll("\\", "")),
        };
      } catch {
        // continue
      }
    }
  }

  // attempt 6: chromium 000005.ldb on Windows
  {
    const matchRegex = /Keyring[0-9][^\}]*(\{[^\{\}]*\\"\})/gu;
    const captureRegex = /Keyring[0-9][^\}]*(\{[^\{\}]*\\"\})/u;
    const ivRegex =
      /\\"iv.{1,4}[^A-Za-z0-9+\/]{1,10}([A-Za-z0-9+\/]{10,40}=*)/u;
    const dataRegex = /\\"[^":,is]*\\":\\"([A-Za-z0-9+\/]*=*)/u;
    const saltRegex =
      /,\\"salt.{1,4}[^A-Za-z0-9+\/]{1,10}([A-Za-z0-9+\/]{10,100}=*)/u;

    const rawMatches = data.match(matchRegex);
    if (rawMatches) {
      const vaults = dedupe(
        rawMatches
          .map((m) => m.match(captureRegex)![1])
          .map((s) =>
            [dataRegex, ivRegex, saltRegex].map((r) => s.match(r))
          )
          .filter(
            ([d, i, s]) =>
              d && d.length > 1 && i && i.length > 1 && s && s.length > 1
          )
          .map(([d, i, s]) => ({
            data: d![1],
            iv: i![1],
            salt: s![1],
          }))
      );
      if (vaults.length) {
        if (vaults.length > 1) console.log("Found multiple vaults!");
        return vaults[0];
      }
    }
  }

  // attempt 7: split state format (chromium 000004.log on Windows)
  {
    const vaultRegex =
      /KeyringController[\s\S]*?"vault":"((?:[^"\\]|\\.)*)"/g;
    const vaults: Vault[] = [];
    let match;

    while ((match = vaultRegex.exec(data)) !== null) {
      try {
        const vaultString = JSON.parse(`"${match[1]}"`);
        const json = JSON.parse(vaultString);
        vaults.push(json);
      } catch {
        // continue
      }
    }

    const dedupedVaults = dedupe(vaults);
    if (dedupedVaults.length) {
      if (dedupedVaults.length > 1) console.log("Found multiple vaults!");
      return dedupedVaults[0];
    }
  }

  return null;
}

// ─── Vault validation ────────────────────────────────────────────────────────

function isVaultValid(vault: unknown): vault is Vault {
  return (
    typeof vault === "object" &&
    vault !== null &&
    ["data", "iv", "salt"].every(
      (e) => typeof (vault as Record<string, unknown>)[e] === "string"
    )
  );
}

// ─── Decryption ──────────────────────────────────────────────────────────────

function decodeMnemonic(mnemonic: string | number[]): string {
  if (typeof mnemonic === "string") return mnemonic;
  return Buffer.from(mnemonic).toString("utf8");
}

async function decryptVault(
  password: string,
  vault: Vault
): Promise<Keyring[]> {
  const keyrings = (await passworder.decrypt(
    password,
    JSON.stringify(vault)
  )) as Keyring[];

  return keyrings.map((keyring) => {
    if ("mnemonic" in keyring.data) {
      return {
        ...keyring,
        data: {
          ...keyring.data,
          mnemonic: decodeMnemonic(keyring.data.mnemonic!),
        },
      };
    }
    return keyring;
  });
}

// ─── CLI ─────────────────────────────────────────────────────────────────────

function printUsage(): void {
  console.log(`
MetaMask Vault Decryptor (Safe CLI)
====================================
Runs 100% locally. No network calls. No data leaves your machine.

Usage:
  node dist/decrypt.js --vault <vault.json> --password <your-password>
  node dist/decrypt.js --file <000003.log> --password <your-password>

Options:
  --vault <path>     Path to a JSON file with vault data ({ data, iv, salt })
  --file <path>      Path to a raw Chrome/Chromium log or ldb file
  --password <pass>  Your MetaMask password
  --help             Show this help message
`);
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--help") || args.length === 0) {
    printUsage();
    process.exit(0);
  }

  const vaultIdx = args.indexOf("--vault");
  const fileIdx = args.indexOf("--file");
  const passIdx = args.indexOf("--password");

  if (passIdx === -1 || !args[passIdx + 1]) {
    console.error("Error: --password is required.");
    process.exit(1);
  }

  const password = args[passIdx + 1];
  let vault: Vault;

  if (vaultIdx !== -1 && args[vaultIdx + 1]) {
    // Direct vault JSON file
    const filePath = resolve(args[vaultIdx + 1]);
    const raw = readFileSync(filePath, "utf-8");
    const parsed = JSON.parse(raw);

    if (!isVaultValid(parsed)) {
      console.error(
        "Error: Vault JSON must have 'data', 'iv', and 'salt' string fields."
      );
      process.exit(1);
    }
    vault = parsed;
  } else if (fileIdx !== -1 && args[fileIdx + 1]) {
    // Raw browser log/ldb file
    const filePath = resolve(args[fileIdx + 1]);
    const raw = readFileSync(filePath, "utf-8");
    const extracted = extractVaultFromFile(raw);

    if (!extracted || !isVaultValid(extracted)) {
      console.error("Error: Could not find valid vault data in the file.");
      process.exit(1);
    }
    vault = extracted;
  } else {
    console.error("Error: Provide either --vault or --file.");
    printUsage();
    process.exit(1);
  }

  console.log("\nVault found. Decrypting...\n");

  try {
    const keyrings = await decryptVault(password, vault);

    for (const keyring of keyrings) {
      console.log(`Keyring type: ${keyring.type}`);
      if (keyring.data.mnemonic) {
        console.log(`Mnemonic (seed phrase): ${keyring.data.mnemonic}`);
      }
      if (keyring.data.mnemonic === undefined) {
        console.log("Data:", JSON.stringify(keyring.data, null, 2));
      }
      console.log("---");
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (message === "Incorrect password") {
      console.error("Error: Incorrect password.");
    } else {
      console.error("Error decrypting vault:", message);
    }
    process.exit(1);
  }
}

main();
