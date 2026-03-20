import os from "os";

export function clearScreen(): void {
  process.stdout.write("\x1Bc");
}

export function setNumThreads(userThreads: number): number {
  const cpus = os.cpus().length;
  if (userThreads <= 0 || userThreads > cpus) {
    return cpus;
  }
  return userThreads;
}

export function isAllVaultsCracked(
  vaults: { decrypted: boolean }[]
): boolean {
  return vaults.every((v) => v.decrypted);
}
