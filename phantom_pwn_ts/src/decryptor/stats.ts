export function printStats(
  elapsedMs: number,
  crackedCount: number,
  validVaultCount: number,
  linesProcessed: number,
  exitProgram: boolean
): void {
  const elapsedSec = elapsedMs / 1000;
  const hours = Math.floor(elapsedSec / 3600);
  const minutes = Math.floor((elapsedSec % 3600) / 60);
  const seconds = Math.floor(elapsedSec % 60);
  const linesPerSecond = elapsedSec > 0 ? linesProcessed / elapsedSec : 0;

  const pad = (n: number) => n.toString().padStart(2, "0");
  const timestamp = new Date().toISOString();
  console.error(
    `${timestamp} Decrypted: ${crackedCount}/${validVaultCount} ${linesPerSecond.toFixed(2)} h/s ${pad(hours)}h:${pad(minutes)}m:${pad(seconds)}s`
  );

  if (exitProgram) {
    console.log("");
    setTimeout(() => process.exit(0), 100);
  }
}

export function monitorPrintStats(
  getState: () => { crackedCount: number; linesProcessed: number },
  startTime: number,
  validVaultCount: number,
  intervalSec: number,
  abortSignal: AbortSignal
): void {
  if (intervalSec <= 0) return;

  const timer = setInterval(() => {
    if (abortSignal.aborted) {
      clearInterval(timer);
      const state = getState();
      printStats(
        Date.now() - startTime,
        state.crackedCount,
        validVaultCount,
        state.linesProcessed,
        true
      );
      return;
    }
    const state = getState();
    printStats(
      Date.now() - startTime,
      state.crackedCount,
      validVaultCount,
      state.linesProcessed,
      false
    );
  }, intervalSec * 1000);

  abortSignal.addEventListener("abort", () => {
    clearInterval(timer);
    const state = getState();
    printStats(
      Date.now() - startTime,
      state.crackedCount,
      validVaultCount,
      state.linesProcessed,
      true
    );
  });
}
