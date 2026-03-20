# Wallet Recovery Tools

Local-only tools for recovering your own cryptocurrency wallet funds. **No network calls** — everything runs on your machine.

---

## Tools

### 1. [vault-decryptor-safe](./vault-decryptor-safe)

Decrypt MetaMask vault data using your **known password**. Based on the [official MetaMask vault-decryptor](https://github.com/MetaMask/vault-decryptor).

```bash
cd vault-decryptor-safe
yarn install && yarn build

# Decrypt with vault JSON
node dist/decrypt.js --vault vault.json --password "your-password"

# Decrypt from Chrome log/ldb file
node dist/decrypt.js --file 000003.log --password "your-password"
```

**Where to find your vault data:**
- Chrome DevTools on MetaMask extension → Console → `chrome.storage.local.get('data', r => console.log(r.data))`
- Or raw LevelDB files in your Chrome profile under `Local Storage/leveldb/`

---

### 2. [phantom_pwn_ts](./phantom_pwn_ts)

Phantom wallet vault decryptor & extractor. TypeScript port of [cyclone-github/phantom_pwn](https://github.com/cyclone-github/phantom_pwn).

**Extractor** — extracts vault hash from Phantom's LevelDB storage:

```bash
cd phantom_pwn_ts
yarn install && yarn build

node dist/extractor/index.js /path/to/phantom/vault/dir
```

Default Phantom vault locations:
| OS | Path |
|---|---|
| Linux | `~/.config/google-chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/` |
| macOS | `~/Library/Application Support/Google/Chrome/Default/Local Extension Settings/bfnaelmomeimhlpmgjnjophhpkkoljpa/` |
| Windows | `%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa\` |

**Decryptor** — decrypts the extracted vault with a wordlist:

```bash
node dist/decryptor/index.js -h vault.json -w wordlist.txt -o output.txt
```

---

## Disclaimer

These tools are intended **only** for recovering your own wallets. Do not use them on wallets you do not own.

## License

- vault-decryptor-safe: ISC (based on MetaMask's vault-decryptor)
- phantom_pwn_ts: GPL-2.0 (port of cyclone-github/phantom_pwn)
