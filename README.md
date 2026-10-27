# Fuzz-testing OpenZeppelin's ERC-7786 N-of-M bridge

*A ForkProof security case study, October 2026.*

OpenZeppelin's `ERC7786OpenBridge` sends a cross-chain message through **M independent bridges** (Axelar,
Wormhole, …) and only delivers it on the destination chain once **N of them agree**. If that counting logic is
wrong, a single compromised bridge or an outsider could get a message executed, or get it executed twice.

We built an isolated property-based test harness around the exact in-scope code and tried to break those
guarantees. **We found no exploitable vulnerability.** This repository contains the harness so anyone can
reproduce the results.

> "No finding" is not a guarantee of security. It means these properties held under the tests below.

## Scope

| | |
|---|---|
| Contract | [`ERC7786OpenBridge.sol`](https://github.com/OpenZeppelin/openzeppelin-community-contracts/blob/0361935dc5edd233adbb9fbae5871ccbb8c739d8/contracts/crosschain/ERC7786OpenBridge.sol) (copied unmodified into `src/`) |
| Commit | `0361935dc5edd233adbb9fbae5871ccbb8c739d8` (openzeppelin-community-contracts) |
| Dependencies | OpenZeppelin Contracts `dab8611`, forge-std `60acb7a` (pinned submodules) |
| Compiler | solc 0.8.27, EVM `prague`, optimizer 200 runs |

The copied file's hash is recorded in [PROVENANCE.md](PROVENANCE.md), so you can confirm the test runs against
the real code, not a modified copy.

## How the bridge decides to execute

Each registered gateway calls `receiveMessage(id, sender, payload)` on the destination bridge:

1. `sender` must be exactly the registered remote bridge (canonical address encoding), otherwise it reverts.
2. The message is identified by `keccak256(abi.encode(sender, payload))`.
3. Each registered gateway's first delivery counts once. Anyone else's call does not count.
4. When the count reaches the threshold, the recipient is called. If that call fails, the message can be retried
   by anyone; if it succeeds, the message is marked executed for good.

## What we tested

11 tests, **9,000 randomized fuzz runs**, all passing. Results are in [`results.log`](results.log).

| # | Property | Result |
|---|---|---|
| P1 | For any order of gateway, duplicate-gateway and outsider deliveries, the message executes **exactly once**, and only after **N distinct registered gateways** delivered it (3,000 random orderings) | holds |
| P2 | Outsiders can never move the counter | holds |
| P3 | Any sender other than the canonical registered remote bridge is rejected, including non-canonical encodings with trailing bytes (3,000 random senders) | holds |
| P6 | A gateway removed and re-added cannot count twice | holds |
| P9 | A recipient re-entering the bridge during execution cannot cause a second execution | holds |
| P10 | After a failed execution anyone can retry; the retry executes exactly once and late gateways do not re-execute | holds |

## Design observations (not exploitable by an outsider)

These are behaviours worth knowing when you deploy the bridge. None lets an untrusted party execute or replay
a message.

- **P4: the dedup key covers the raw payload bytes.** `abi.decode` accepts trailing bytes, so two byte-encodings
  of the same logical message get separate counters. Executing the variant still needs N gateways to deliver the
  identical variant bytes, which means the gateways themselves would have to collude. The source bridge always
  produces canonical `abi.encode` output, so users cannot create variants.
- **P5: a removed gateway's earlier delivery still counts.** This is documented in the contract's own comments
  (`_removeGateway`). Operators rotating a compromised gateway should treat its in-flight receipts as valid.
- **P7: the recipient's chain id is not checked on arrival.** The destination executes whatever EVM address the
  payload names. A wrong chain only matters if a gateway delivers a message to the wrong chain.
- **P8: a malformed recipient blocks only its own message.** If the recipient is not a 20-byte EVM address, every
  threshold-crossing delivery reverts. Only the original sender's message is affected.

## Run it yourself

Requires [Foundry](https://book.getfoundry.sh/).

```bash
git clone --recursive https://github.com/ForkProof/oz-erc7786-fuzz
cd oz-erc7786-fuzz
forge test -vv
```

We run third-party code in a throwaway container with no network access. The test needs no network once the
compiler is downloaded.

## About ForkProof

ForkProof reviews smart contracts and key-custody setups before launch: protocol logic, signing flows and
secret handling. Contact: see [forkproof.github.io](https://forkproof.github.io).

## License

MIT. `src/ERC7786OpenBridge.sol` is © OpenZeppelin, MIT-licensed, included unmodified for reproducibility.
