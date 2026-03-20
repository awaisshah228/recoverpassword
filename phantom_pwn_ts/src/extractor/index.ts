import { parseArgs } from "util";
import { readdirSync, readFileSync, statSync } from "fs";
import path from "path";
import bs58 from "bs58";
import { ClassicLevel } from "classic-level";

/*
Cyclone's Phantom Vault Extractor
https://github.com/cyclone-github/phantom_pwn
TypeScript port of the original Go tool

GNU General Public License v2.0
*/

interface EncryptedKey {
  digest: string;
  encrypted: string;
  iterations: number;
  kdf: string;
  nonce: string;
  salt: string;
}

interface Vault0 {
  expiry: number;
  value: string;
}

interface Vault1 {
  encryptedKey: EncryptedKey;
  version: number;
}

function clearScreen(): void {
  process.stdout.write("\x1Bc");
}

function versionFunc(): void {
  console.error(
    "Cyclone's Phantom Vault Extractor v1.0.0-ts; 2025-10-22\nhttps://github.com/cyclone-github/phantom_pwn\n"
  );
}

function helpFunc(): void {
  versionFunc();
  console.error(`Example Usage:
node dist/extractor/index.js [--version] [--help] <phantom_vault_dir>
node dist/extractor/index.js bfnaelmomeimhlpmgjnjophhpkkoljpa/

Default Phantom vault locations for Chrome extensions:

Linux:
/home/$USER/.config/google-chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/

Mac:
Library>Application Support>Google>Chrome>Default>Local Extension Settings>bfnaelmomeimhlpmgjnjophhpkkoljpa

Windows:
C:\\Users\\$USER\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Local Extension Settings\\bfnaelmomeimhlpmgjnjophhpkkoljpa\\`);
}

function printWelcomeScreen(): void {
  console.log(" ----------------------------------------------------- ");
  console.log("|        Cyclone's Phantom Vault Hash Extractor       |");
  console.log("|        Use Phantom Vault Decryptor to decrypt       |");
  console.log("|    https://github.com/cyclone-github/phantom_pwn    |");
  console.log(" ----------------------------------------------------- ");
}

function detectVersion(data: string): number {
  if (data.includes('"encryptedKey":')) return 1;
  if (data.includes('"expiry":')) return 0;
  return -1;
}

function printJSONVault(entry: Vault1): void {
  const ek = entry.encryptedKey;
  if (ek.digest && ek.encrypted && ek.iterations && ek.kdf && ek.nonce && ek.salt) {
    console.log(JSON.stringify(entry));
  }
}

function printHashcatHash(vault: Vault1): void {
  const saltDecoded = bs58.decode(vault.encryptedKey.salt);
  const nonceDecoded = bs58.decode(vault.encryptedKey.nonce);
  const encryptedDecoded = bs58.decode(vault.encryptedKey.encrypted);

  const saltB64 = Buffer.from(saltDecoded).toString("base64");
  const nonceB64 = Buffer.from(nonceDecoded).toString("base64");
  const encryptedB64 = Buffer.from(encryptedDecoded).toString("base64");

  if (vault.encryptedKey.kdf.toLowerCase() === "scrypt") {
    console.log(" ----------------------------------------------------- ");
    console.log("|          hashcat -m 26650 hash (scrypt kdf)         |");
    console.log(" ----------------------------------------------------- ");
    console.log(`PHANTOM:4096:8:1:${saltB64}:${nonceB64}:${encryptedB64}`);
    return;
  }

  if (vault.encryptedKey.kdf.toLowerCase() === "pbkdf2") {
    console.log(" ----------------------------------------------------- ");
    console.log("|          hashcat -m 30010 hash (pbkdf2 kdf)         |");
    console.log(" ----------------------------------------------------- ");
    console.log(`$phantom$${saltB64}$${nonceB64}$${encryptedB64}`);

    console.log(" ----------------------------------------------------- ");
    console.log("|          hashcat -m 26651 hash (pbkdf2 kdf)         |");
    console.log(" ----------------------------------------------------- ");
    console.log(`PHANTOM:10000:${saltB64}:${nonceB64}:${encryptedB64}`);
  }
}

function processLevelDBValue(data: string): void {
  const version = detectVersion(data);

  switch (version) {
    case 1: {
      try {
        const vault1: Vault1 = JSON.parse(data);
        printJSONVault(vault1);
        printHashcatHash(vault1);
      } catch { /* skip */ }
      break;
    }
    case 0: {
      try {
        const vault0: Vault0 = JSON.parse(data);
        const cleanStr = vault0.value.replace(/\\/g, "");
        const encryptedKey: EncryptedKey = JSON.parse(cleanStr);
        const vault1: Vault1 = {
          encryptedKey,
          version: 0,
        };
        printJSONVault(vault1);
        printHashcatHash(vault1);
      } catch { /* skip */ }
      break;
    }
    default:
      break;
  }
}

function filterPrintableBytes(data: Buffer): string {
  return Array.from(data)
    .map((b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : "."))
    .join("");
}

function dumpRawLDBFiles(dirPath: string): void {
  const entries = readdirSync(dirPath, { recursive: true }) as string[];
  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry);
    try {
      const stat = statSync(fullPath);
      if (!stat.isDirectory() && fullPath.endsWith(".ldb")) {
        const data = readFileSync(fullPath);
        const filtered = filterPrintableBytes(data);
        // Try to find JSON objects in the raw data
        const jsonMatches = filtered.match(/\{[^{}]*"encryptedKey"[^{}]*\{[^}]*\}[^}]*\}/g) ||
          filtered.match(/\{[^{}]*"expiry"[^{}]*\}/g);
        if (jsonMatches) {
          for (const match of jsonMatches) {
            processLevelDBValue(match);
          }
        }
      }
    } catch { /* skip */ }
  }
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    options: {
      cyclone: { type: "boolean", default: false },
      version: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
    allowPositionals: true,
    strict: false,
  });

  clearScreen();

  if (values.version) {
    versionFunc();
    process.exit(0);
  }
  if (values.cyclone) {
    console.log(Buffer.from("Q29kZWQgYnkgY3ljbG9uZSA7KQo=", "base64").toString());
    process.exit(0);
  }
  if (values.help) {
    helpFunc();
    process.exit(0);
  }

  const ldbDir = positionals[0];
  if (!ldbDir) {
    console.error("Error: Phantom vault directory is required");
    helpFunc();
    process.exit(1);
  }

  printWelcomeScreen();

  try {
    const db = new ClassicLevel<string, string>(ldbDir, {
      createIfMissing: false,
      valueEncoding: "utf8",
    });

    for await (const [_key, value] of db.iterator()) {
      processLevelDBValue(value);
    }

    await db.close();
  } catch (err) {
    console.error("Error opening Vault:", err);
    console.log("Attempting to dump raw .ldb files...");
    dumpRawLDBFiles(ldbDir);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
