# ITB Fortran Binding - Easy Mode Benchmark Results

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

Throughput (MB/s) of `e%encrypt` / `e%decrypt` / `e%encrypt_auth` /
`e%decrypt_auth` over the libitb c-shared library through the Fortran
binding's `iso_c_binding`-emitted FFI surface. Single + Triple
Ouroboros at 1024-bit ITB key width on a 16 MiB
non-deterministic-fill payload, four ops per primitive. The MAC slot
is bound to **HMAC-BLAKE3** -- the lightest authenticated-mode
overhead among the three shipping MACs (the `encrypt_auth` row sits
within a few percent of the matching `encrypt` row).

The harness lives under [.](.) -- see [README.md](README.md) for
invocation, environment variables, and the per-case output format.
The default measurement window is 5 seconds per case
(`ITB_BENCH_MIN_SEC=5`), wide enough to absorb the cold-cache /
warm-up transient that distorts shorter windows on the 16 MiB encrypt
/ decrypt path.

Reproduction (from `bindings/fortran/`):

```bash
./build.sh            # builds libitb.so + the binding's src tree
make bench            # builds bench/bin/itb-bench-{single,triple}
./run_bench.sh        # full 4-pass canonical sweep
ITB_LOCKSEED=1 ITB_LOCKBATCH=1 ./run_bench.sh   # Lock Batch performance variant
ITB_LOCKSEED=1 ./run_bench.sh   # equivalent to passes 3 + 4 alone
```

The `ITB_LOCKSEED=1 ITB_LOCKBATCH=1` line selects the Lock Batch
performance variant of Lock Soup; the `ITB_LOCKSEED=1` line retains
the baseline Lock Soup arm.

Pass `FC=ifx` to drive Intel's compiler instead of gfortran:

```bash
FC=ifx make bench
FC=ifx ./run_bench.sh
```

## FFI overhead vs. native Go

The Fortran path adds a `bind(C)` wrapper jump per FFI call, the C
ABI crossing into Go via `libitb.so`, and a per-call
`allocatable`-array copy of the ciphertext / plaintext bytes back
into a Fortran-managed buffer. The encryptor caches a per-instance
output buffer on the Go side and pre-allocates from a 1.25x upper
bound on the empirical ITB ciphertext-expansion factor (<= 1.155
across every primitive / mode / nonce / payload-size combination) so
the hot loop avoids the size-probe round-trip the process-global FFI
helpers use. The cached bytes are zeroed on grow and on
`e%close()` / `e%destroy()`, so residual ciphertext / plaintext
cannot linger in heap garbage between cipher calls.

The numbers below ride the default build (no opt-out tags). On hosts
without AVX-512+VL the Go side automatically nil-routes the 4-lane
batched chain-absorb arm so the per-pixel hash falls through to the
upstream stdlib asm via the single `Func` -- see the build-tag
table in [`../README.md`](../README.md) for the `-tags=noitbasm` opt-outs.

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, gfortran 16.1.1)

### ITB Single 1024-bit (security: P x 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 179 | 268 | 173 | 249 |
| **Areion-SoEM-512** | 512 | PRF | 194 | 283 | 179 | 261 |
| **BLAKE2b-256** | 256 | PRF | 95 | 109 | 89 | 105 |
| **BLAKE2b-512** | 512 | PRF | 132 | 166 | 125 | 155 |
| **BLAKE2s** | 256 | PRF | 102 | 121 | 99 | 116 |
| **BLAKE3** | 256 | PRF | 121 | 147 | 116 | 142 |
| **AES-CMAC** | 128 | PRF | 180 | 254 | 168 | 232 |
| **SipHash-2-4** | 128 | PRF | 146 | 189 | 139 | 183 |
| **ChaCha20** | 256 | PRF | 110 | 128 | 103 | 124 |
| **Mixed** | 256 | PRF | 108 | 128 | 103 | 124 |

### ITB Triple 1024-bit (security: P x 2^(3x1024) = P x 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 252 | 304 | 223 | 284 |
| **Areion-SoEM-512** | 512 | PRF | 260 | 316 | 229 | 293 |
| **BLAKE2b-256** | 256 | PRF | 105 | 111 | 99 | 105 |
| **BLAKE2b-512** | 512 | PRF | 157 | 172 | 137 | 151 |
| **BLAKE2s** | 256 | PRF | 106 | 108 | 107 | 118 |
| **BLAKE3** | 256 | PRF | 140 | 153 | 131 | 150 |
| **AES-CMAC** | 128 | PRF | 238 | 280 | 213 | 262 |
| **SipHash-2-4** | 128 | PRF | 182 | 204 | 165 | 191 |
| **ChaCha20** | 256 | PRF | 125 | 135 | 118 | 131 |
| **Mixed** | 256 | PRF | 123 | 133 | 117 | 130 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, gfortran 16.1.1, Lock Seed + Lock Batch mode)

The Lock Batch performance variant (`ITB_LOCKSEED=1 ITB_LOCKBATCH=1` /
`e%set_lock_batch(1)`) batches the per-chunk Lock Soup overlay
derivation, reducing per-chunk PRF invocations without affecting
security under the PRF assumption. Numbers below run with
`ITB_LOCKSEED=1 ITB_LOCKBATCH=1`, default nonce, 16 MiB payload,
`ITB_BENCH_MIN_SEC=5`.

### ITB Single 1024-bit (security: P x 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 95 | 122 | 97 | 115 |
| **Areion-SoEM-512** | 512 | PRF | 112 | 136 | 108 | 132 |
| **BLAKE2b-256** | 256 | PRF | 63 | 70 | 61 | 69 |
| **BLAKE2b-512** | 512 | PRF | 89 | 103 | 85 | 100 |
| **BLAKE2s** | 256 | PRF | 67 | 74 | 64 | 73 |
| **BLAKE3** | 256 | PRF | 72 | 80 | 69 | 78 |
| **AES-CMAC** | 128 | PRF | 91 | 107 | 88 | 104 |
| **SipHash-2-4** | 128 | PRF | 81 | 93 | 78 | 90 |
| **ChaCha20** | 256 | PRF | 67 | 75 | 66 | 73 |
| **Mixed** | 256 | PRF | 72 | 81 | 70 | 80 |

### ITB Triple 1024-bit (security: P x 2^(3x1024) = P x 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 150 | 192 | 157 | 184 |
| **Areion-SoEM-512** | 512 | PRF | 187 | 212 | 163 | 197 |
| **BLAKE2b-256** | 256 | PRF | 81 | 85 | 79 | 83 |
| **BLAKE2b-512** | 512 | PRF | 126 | 135 | 119 | 132 |
| **BLAKE2s** | 256 | PRF | 87 | 92 | 84 | 90 |
| **BLAKE3** | 256 | PRF | 96 | 105 | 93 | 100 |
| **AES-CMAC** | 128 | PRF | 147 | 160 | 138 | 157 |
| **SipHash-2-4** | 128 | PRF | 121 | 130 | 116 | 127 |
| **ChaCha20** | 256 | PRF | 88 | 92 | 85 | 91 |
| **Mixed** | 256 | PRF | 97 | 104 | 94 | 102 |

## Intel Core i7-11700K (16 HT, native Linux, c-shared mode, gfortran 16.1.1, LockSeed mode)

The dedicated lockSeed channel (`e%set_lock_seed(1)` /
`ITB_LOCKSEED=1`) auto-couples bit-soup + lock-soup on the
on-direction. Numbers below run with all three overlays active.

### ITB Single 1024-bit (security: P x 2^1024)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 61 | 72 | 61 | 71 |
| **Areion-SoEM-512** | 512 | PRF | 52 | 57 | 51 | 56 |
| **BLAKE2b-256** | 256 | PRF | 44 | 46 | 43 | 46 |
| **BLAKE2b-512** | 512 | PRF | 48 | 50 | 47 | 50 |
| **BLAKE2s** | 256 | PRF | 45 | 48 | 44 | 48 |
| **BLAKE3** | 256 | PRF | 44 | 47 | 45 | 47 |
| **AES-CMAC** | 128 | PRF | 75 | 86 | 73 | 84 |
| **SipHash-2-4** | 128 | PRF | 68 | 77 | 66 | 75 |
| **ChaCha20** | 256 | PRF | 46 | 49 | 45 | 48 |
| **Mixed** | 256 | PRF | 43 | 55 | 49 | 55 |

### ITB Triple 1024-bit (security: P x 2^(3x1024) = P x 2^3072)

| Hash | Width | Crypto | Encrypt | Decrypt | Encrypt + MAC | Decrypt + MAC |
|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 256 | PRF | 61 | 66 | 61 | 65 |
| **Areion-SoEM-512** | 512 | PRF | 54 | 55 | 52 | 55 |
| **BLAKE2b-256** | 256 | PRF | 44 | 45 | 43 | 45 |
| **BLAKE2b-512** | 512 | PRF | 48 | 49 | 47 | 49 |
| **BLAKE2s** | 256 | PRF | 46 | 47 | 45 | 46 |
| **BLAKE3** | 256 | PRF | 45 | 47 | 44 | 46 |
| **AES-CMAC** | 128 | PRF | 78 | 83 | 76 | 82 |
| **SipHash-2-4** | 128 | PRF | 71 | 74 | 68 | 73 |
| **ChaCha20** | 256 | PRF | 49 | 49 | 40 | 45 |
| **Mixed** | 256 | PRF | 49 | 51 | 48 | 51 |

## Notes

- The first row in every Single-Ouroboros pass typically shows a
  transient asymmetry between encrypt and decrypt. This is the
  cold-cache + first-iteration warmup absorbed imperfectly even at
  5-second windows; subsequent rows in the same pass run on warm
  caches and report symmetric encrypt-vs-decrypt numbers. Re-running
  the same primitive in isolation
  (`ITB_BENCH_FILTER=areion256 ITB_BENCH_MIN_SEC=20 ./bench/bin/itb-bench-single`)
  normalises the asymmetry.
- The LockSeed arms cap throughput in a narrow band because the
  dedicated lockseed slot auto-engages BitSoup + LockSoup; the bit-
  level split + per-chunk PRF-keyed bit-permutation overlay together
  dominate the per-byte cost. Wider hash output produces more
  per-pixel work and tends to sit closer to the floor under the
  lockseed-mode multiplier.
- Triple Ouroboros exceeds Single Ouroboros throughput on most
  primitives in the no-LockSeed arms because the seven-seed split
  exposes additional internal parallelism opportunities to libitb's
  worker pool while the on-the-wire chunk count remains the same.
  The effect collapses under LockSeed mode where the per-chunk
  overlay cost dominates and the two arms converge.
- Bench cases run sequentially per pass; libitb's internal worker
  pool (`itb_set_max_workers(0)` -> all CPUs) processes each case's
  chunk-level parallelism within the case's wall-clock window.
- gfortran (16.1.1) and ifx (Intel oneAPI 2025.0.4) both build the
  binding cleanly under strict flags; numbers above are gfortran.
  ifx-built binaries measure roughly 15-48 % slower across the
  full bench matrix on this host (not within the +/-10 %
  dual-toolchain-equivalent band). The per-call cost is dominated
  by FFI plumbing -- `c_loc`, array assignment, `move_alloc`
  inside the wrapper layer -- and gfortran's implementation of
  these primitives produces tighter codegen on this codebase. The
  Fortran cipher work itself (encrypt / decrypt loops) lives
  entirely on the libitb / Go side and does not vary by Fortran
  toolchain. To reproduce under ifx, source the oneAPI activation
  script and rebuild via `make clean && FC=ifx ./build.sh && FC=ifx make bench`.
