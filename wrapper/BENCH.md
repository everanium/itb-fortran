# ITB Format-Deniability Wrapper Benchmark Results — Fortran Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of three outer keystream ciphers — AES-128-CTR (stdlib AES-NI on x86-64), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), or SipHash-2-4 in CTR mode (`dchest/siphash` PRF + custom counter loop). The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (zero allocation steady state); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's callback-driven Streaming AEAD API or a User-Driven Loop emitting framed chunks through the wrap-stream writer.

### Concurrency note — outer cipher single-thread bottleneck on big-iron

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path adds no allocation pressure. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR runs single-threaded on one core. ChaCha20 (~700 MB/s peak on a single core via `x/crypto/chacha20`) and SipHash-CTR (~250–280 MB/s peak via the `dchest/siphash` PRF + 16-byte refill loop) become the bottleneck once ITB's Triple decrypt path approaches ~1 GB/s on big-iron. AES-128-CTR retains hardware acceleration on every HT thread the underlying goroutine lands on and stays out of the critical path even there.

The Fortran binding's wrapper layer routes XOR through the libitb FFI — it neither parallelises the keystream itself nor offloads to a different thread pool. The single-thread ceiling is therefore the wrapper-layer bottleneck on hosts where ITB outpaces the chosen outer cipher.

### Compiler note — gfortran is the reference baseline

The Fortran binding ships under both gfortran (default) and ifx (Intel oneAPI). gfortran is the canonical reference for the BENCH.md tables — every cell below is measured under gfortran's per-FFI-call cost profile. ifx measures roughly **15–48% slower** than gfortran on the existing bench surfaces (see `bench/BENCH.md` for the gfortran-vs-ifx comparison). The wrapper bench surface inherits the same compiler asymmetry; reproduction with ifx requires `make FC=ifx bench` and the `-heap-arrays 0` flag the Makefile auto-applies under ifx.

## Reproduction

```sh
cd bindings/fortran
make bench
ITB_BENCH_MIN_SEC=5 ./bench/bin/itb-bench-wrapper
```

Filter examples:

```sh
ITB_BENCH_FILTER=bench_wrapper_only      ITB_BENCH_MIN_SEC=5 ./bench/bin/itb-bench-wrapper
ITB_BENCH_FILTER=bench_message_single    ITB_BENCH_MIN_SEC=5 ./bench/bin/itb-bench-wrapper
ITB_BENCH_FILTER=bench_streaming_triple  ITB_BENCH_MIN_SEC=5 ./bench/bin/itb-bench-wrapper
```

Sub-bench count: **102**. (6 wrapper only round-trip + 24 Message Single + 24 Message Triple + 24 Streaming Single + 24 Streaming Triple. Each Streaming-* set: 4 modes × 3 ciphers × 2 directions; the Fortran binding has no Streaming No MAC IO-Driven mode, replaced by User-Driven Loop variants.)

## Configuration

* Outer cipher path: AES-128-CTR (stdlib + AES-NI), ChaCha20 (RFC8439) (`golang.org/x/crypto/chacha20`), SipHash-2-4 in CTR mode (`dchest/siphash` + custom counter loop).
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb_set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via array assignment; the copy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.
* Compiler: gfortran (default; `-O2`). ifx alternative (`make FC=ifx bench`) measures 15–48% slower.

## Results

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (zero alloc) MB/s |
|---|---|---|
| **AES-128-CTR** | 2227 | **2405** |
| **ChaCha20** | 557 | **555** |
| **SipHash-CTR** | 475 | **473** |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 172 | 235 | 135 | 172 | 131 | 163 |
| **Easy** MAC Authenticated | 164 | 222 | 130 | 166 | 123 | 154 |
| **Low-Level** No MAC | 178 | 241 | 137 | 175 | 132 | 164 |
| **Low-Level** MAC Authenticated | 164 | 222 | 130 | 153 | 124 | 155 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Easy** No MAC | 235 | 272 | 170 | 190 | 161 | 178 |
| **Easy** MAC Authenticated | 212 | 254 | 159 | 182 | 150 | 169 |
| **Low-Level** No MAC | 237 | 275 | 172 | 192 | 162 | 179 |
| **Low-Level** MAC Authenticated | 209 | 257 | 159 | 183 | 151 | 172 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 161 | 221 | 130 | 163 | 123 | 155 |
| **Streaming AEAD Low-Level** IO-Driven | 163 | 221 | 129 | 166 | 124 | 156 |
| **Streaming Easy** No MAC, User-Driven Loop | 174 | 239 | 136 | 172 | 130 | 161 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 176 | 242 | 136 | 175 | 132 | 165 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size)

| Mode | AES Enc | AES Dec | ChaCha Enc | ChaCha Dec | SipHash Enc | SipHash Dec |
|---|---|---|---|---|---|---|
| **Streaming AEAD Easy** IO-Driven | 211 | 253 | 158 | 180 | 150 | 169 |
| **Streaming AEAD Low-Level** IO-Driven | 214 | 256 | 159 | 182 | 151 | 171 |
| **Streaming Easy** No MAC, User-Driven Loop | 234 | 268 | 171 | 190 | 160 | 176 |
| **Streaming Low-Level** No MAC, User-Driven Loop | 235 | 273 | 172 | 191 | 162 | 178 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
