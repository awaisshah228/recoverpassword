export function versionFunc(): void {
  console.error(
    "Cyclone's Phantom Vault Decryptor v1.0.0-ts; 2025-10-22\nhttps://github.com/cyclone-github/phantom_pwn\n"
  );
}

export function helpFunc(): void {
  versionFunc();
  console.error(`Example Usage:

-w {wordlist} (omit -w to read from stdin)
-h {phantom_wallet_hash}
-o {output} (omit -o to write to stdout)
-t {cpu threads}
-s {print status every nth sec}

-version (version info)
-help (usage instructions)

node dist/decryptor/index.js -h {phantom_wallet_hash} -w {wordlist} -o {output} -t {cpu threads} -s {print status every nth sec}

node dist/decryptor/index.js -h phantom.txt -w wordlist.txt -o cracked.txt -t 16 -s 10

cat wordlist | node dist/decryptor/index.js -h phantom.txt

node dist/decryptor/index.js -h phantom.txt -w wordlist.txt -o output.txt`);
}

export function printWelcomeScreen(
  vaultFile: string,
  wordlistFile: string,
  validVaultCount: number,
  numThreads: number
): void {
  console.error(" ----------------------------------------------- ");
  console.error("|       Cyclone's Phantom Vault Decryptor       |");
  console.error("| https://github.com/cyclone-github/phantom_pwn |");
  console.error(" ----------------------------------------------- ");
  console.error();
  console.error(`Vault file:\t${vaultFile}`);
  console.error(`Valid Vaults:\t${validVaultCount}`);
  console.error(`CPU Threads:\t${numThreads}`);

  if (!wordlistFile) {
    console.error("Wordlist:\tReading stdin");
  } else {
    console.error(`Wordlist:\t${wordlistFile}`);
  }

  console.error("Working...");
}
