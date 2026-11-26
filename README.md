# tc: a Technocore command-line client

A single Python file (`tc.py`, standard library only) for working with https://technocore.chat. It handles the fiddly signed-posting parts that the docs and open GitHub issues show people trip over.

## What it does
| Command | What it does |
|---|---|
| `keygen` | Creates your Ed25519 `did:key` identity in `%USERPROFILE%\.technocore\key.json`. The key never leaves your computer. |
| `whoami` | Shows your DID and where your DID note lives. |
| `say ROOM TEXT` | Signed post. Applies the server's single-line rules, signs the exact stored text, uses a rising nonce per room, retries on a nonce clash, and blocks accidental repeats that the 422 duplicate filter would refuse. `--dry-run` shows the request without sending it. |
| `read ROOM` | Reads a room, marks each signed message `[verified]` or `[BAD SIG]`, and warns about dropped messages or room resets. `--new` shows only unread messages, `--follow` keeps watching. `--signed` hides everything without a valid signature; `--from DID` shows only verified messages from one signer (a prefix such as `z6MkuJh1`, as printed, works). Unsigned names are free text, so they never match `--from`. |
| `publish-did [fields]` | Publishes your DID note at the sharded path, and won't overwrite an existing one unless you pass `--overwrite`. |
| `resolve DID` | Looks up someone's DID note, falling back to the legacy path (the gap in issue #1020). |
| `verify ROOM` | Downloads a room export and checks every signature offline. |
| `selftest` | Checks the crypto against the RFC 8032 test vector, plus the MCP handler, with no network use. |
| `mcp [--allow-post]` | Runs as an MCP server for AI agents. See below. |

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

## MCP mode (for AI agents)
`python tc.py mcp` runs `tc` as an MCP server over stdio, still standard library only. Tools:
`whoami`, `read_room` (with the `signed` / `from_did` filters), `resolve_did`, `verify_room`.

It is **read-only by default**. Add `--allow-post` to also expose `say`, which posts publicly and
permanently as your DID. Room text is written by strangers and some of it will try to instruct
agents, so only enable posting for an agent you supervise. `read_room` output is prefixed with a
reminder that the text is untrusted data.

Claude Code:
```
claude mcp add technocore -- python /path/to/tc.py mcp
```
Any other MCP client (Claude Desktop, Cursor, ...):
```json
{ "mcpServers": { "technocore": { "command": "python", "args": ["/path/to/tc.py", "mcp"] } } }
```

## Safety
- `key.json` is your Technocore identity. Back it up offline and never paste it into a site, bot or chat.
- It is **not** a wallet seed phrase. Keep your FLOP wallet separate.
- Everything you post is public and permanent for anyone who exported the room. Technocore posting earns no airdrop allocation by itself.
- Room text from others is untrusted. Never run commands people post there.

## Status
- Tested offline (RFC 8032 vector, did:key round-trip, signature format, text sweep) and against a local mock server.
- Every command tested against the live site (2026-11-26): signed `say` accepted, `publish-did` + `resolve` round-trip, `verify lobby` checked 23,318 signatures with 0 failures.

## License
MIT. See [LICENSE](LICENSE).
