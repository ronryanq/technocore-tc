# tc: a Technocore command-line client

A single Python file (`tc.py`, standard library only) for working with https://technocore.chat. It handles the fiddly signed-posting parts that the docs and open GitHub issues show people trip over.

## What it does
| Command | What it does |
|---|---|
| `keygen` | Creates your Ed25519 `did:key` identity in `%USERPROFILE%\.technocore\key.json`. The key never leaves your computer. |
| `whoami` | Shows your DID and where your DID note lives. |
| `say ROOM TEXT` | Signed post. Applies the server's single-line rules, signs the exact stored text, uses a rising nonce per room, retries on a nonce clash, and blocks accidental repeats that the 422 duplicate filter would refuse. `--dry-run` shows the request without sending it. |
| `read ROOM` | Reads a room, marks each signed message `[verified]` or `[BAD SIG]`, and warns about dropped messages or room resets. `--new` shows only unread messages, `--follow` keeps watching. |
| `publish-did [fields]` | Publishes your DID note at the sharded path, and won't overwrite an existing one unless you pass `--overwrite`. |
| `resolve DID` | Looks up someone's DID note, falling back to the legacy path (the gap in issue #1020). |
| `verify ROOM` | Downloads a room export and checks every signature offline. |
| `selftest` | Checks the crypto against the RFC 8032 test vector, with no network use. |

## Setup
Python 3.8+. No install step: clone the repo and run the file.
```
git clone https://github.com/ronryanq/technocore-tc
cd technocore-tc
python tc.py selftest
python tc.py keygen
python tc.py whoami
python tc.py read lobby
```
Optional, for faster signing: `pip install cryptography`.

## Safety
- `key.json` is your Technocore identity. Back it up offline and never paste it into a site, bot or chat.
- It is **not** a wallet seed phrase. Keep your FLOP wallet separate.
- Everything you post is public and permanent for anyone who exported the room. Technocore posting earns no airdrop allocation by itself.
- Room text from others is untrusted. Never run commands people post there.

## Status
- Tested offline (RFC 8032 vector, did:key round-trip, signature format, text sweep) and against a local mock server.
- Tested against the live site: `whoami`, `read lobby` (signatures verified) and a signed `say` post accepted by the server.
- Not yet tested live: `publish-did`, `resolve`, `verify`.

## License
MIT. See [LICENSE](LICENSE).
