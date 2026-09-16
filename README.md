# stellar-pool-zk-sdk

Client SDK, published circuit shapes, production Groth16 artifacts, and demos for Stellar privacy pools.

Contracts, Circom **templates**, and auditor-frozen tests live in the [`soroban-privacy-pools`](https://github.com/Polynom-Labs/stellar-privacy-layer-contracts) submodule. This repository may add a new published shape (for example 3×3) without committing to the contracts repo.

npm package: [`@arcanetech/stellar-privacy-pool-zk-sdk`](https://www.npmjs.com/package/@arcanetech/stellar-privacy-pool-zk-sdk) (current line: `0.10.1-rc.2`).

## Layout

| Path | Role |
| --- | --- |
| `client-sdk/` | TypeScript SDK + `client-sdk-cli` |
| `shapes.json` | Catalog of published forms (direct + delegated) |
| `scripts/generate-circuit-main.sh` | Writes a gitignored `generated/*.circom` main |
| `ptau/pot20_final.ptau` | Production Powers of Tau (Git LFS). Do not regenerate. |
| `soroban-privacy-pools/` | Submodule pin to an audited contracts commit |
| `demo.sh`, `demo_noninteractive.sh` | End-to-end flows that call `client-sdk-cli` |

## Local setup

```bash
git submodule update --init
cd client-sdk && npm i && npm run build
```

Wasm crate path dependencies point at the submodule:

```
cryptography = { path = "../../soroban-privacy-pools/libs/cryptography" }
r1cs-compact = { path = "../../soroban-privacy-pools/libs/r1cs-compact" }
```

## Compile a published shape

```bash
./scripts/generate-circuit-main.sh --shape 2x2 --kind direct --out generated/main.circom
make -C soroban-privacy-pools keygen \
  MAIN_CIRCOM=$PWD/generated/main.circom \
  CIRCOM_INCLUDE=$PWD/soroban-privacy-pools/circuits \
  PTAU_PATH=$PWD/ptau/pot20_final.ptau \
  OUTPUT_DIR=$PWD/artifacts
```

Or `./scripts/build-shape.sh 2x2 direct` (also exports the proving key and witness graph).

Test-only `pot19` / `make ptautest` stay in the contracts submodule. This repo never copies `pot19`.

## Artifacts and CDN

Release CI fingerprints each stem from `shapes.json`, rebuilds only changed forms, and uploads them to `stellar/<package-version>/` on Spaces. Unchanged stems keep their previous version folder. The SDK build inlines `artifacts/circuits-manifest.json` so runtime fetches:

`${CDN}/stellar/${manifest.circuits[stem].version}/${fileName}`

`ZK_ARTIFACT_BASE_URL` pointing at a local directory stays a flat folder (`./artifacts` for demos).

## Demos

Set `POOLS_DIR` (default `./soroban-privacy-pools`) for `stellar contract build`, `scripts/deploy-pool.sh`, and `scripts/add_zk_config.sh`. Pass `--shape-json ./shapes.json`. Local proving artifacts come from `./artifacts` or `ZK_ARTIFACT_BASE_URL`.
