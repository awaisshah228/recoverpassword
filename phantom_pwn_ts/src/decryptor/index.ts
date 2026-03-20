import os from "os";
import { parseArgs } from "util";
import { clearScreen, setNumThreads } from "./utils.js";
import { readVaultData } from "./vault.js";
import { versionFunc, helpFunc, printWelcomeScreen } from "./print-welcome.js";
import { monitorPrintStats } from "./stats.js";
import { startProc } from "./process.js";

/*
Cyclone's Phantom Vault Decryptor
https://github.com/cyclone-github/phantom_pwn
TypeScript port of the original Go tool

GNU General Public License v2.0
*/

function main(): void {
  const { values } = parseArgs({
    options: {
      w: { type: "string", default: "" },
      h: { type: "string", default: "" },
      o: { type: "string", default: "" },
      t: { type: "string", default: String(os.cpus().length) },
      s: { type: "string", default: "60" },
      cyclone: { type: "boolean", default: false },
      version: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
    },
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

  const vaultFile = values.h as string;
  const wordlistFile = values.w as string;
  const outputFile = values.o as string;
  const threadCount = parseInt(values.t as string, 10);
  const statsInterval = parseInt(values.s as string, 10);

  if (!vaultFile) {
    console.error("-h (vault file) flag is required");
    console.error("Try running with --help for usage instructions");
    process.exit(1);
  }

  const startTime = Date.now();
  const numThreads = setNumThreads(threadCount);

  const state = { crackedCount: 0, linesProcessed: 0 };
  const abortController = new AbortController();

  // Handle Ctrl+C
  process.on("SIGINT", () => {
    console.error("\nCtrl+C pressed. Shutting down...");
    abortController.abort();
  });
  process.on("SIGTERM", () => {
    abortController.abort();
  });

  const vaults = readVaultData(vaultFile);
  const validVaultCount = vaults.length;

  printWelcomeScreen(vaultFile, wordlistFile, validVaultCount, numThreads);

  monitorPrintStats(
    () => state,
    startTime,
    validVaultCount,
    statsInterval,
    abortController.signal
  );

  startProc(wordlistFile, outputFile, numThreads, vaults, state, abortController).catch(
    (err) => {
      console.error("Error:", err);
      process.exit(1);
    }
  );
}

main();
