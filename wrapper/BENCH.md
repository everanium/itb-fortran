# ITB Format-Deniability Wrapper Benchmark Results — Fortran Binding

> **Security notice.** ITB is an experimental symmetric cipher construction without prior peer review, independent cryptanalysis, or formal certification. The construction's security properties have **not been verified** by independent cryptographers or mathematicians.
>
> PRF-grade hash functions are **required**. No warranty is provided.

**No bespoke cryptography.** ITB introduces no cryptographic primitive of its own — no custom S-box, permutation, or round function. It is a construction over existing primitives, much as PGP composes standard ciphers rather than defining one. Such constructions are not the object of algorithm-level cryptographic certification: national regimes (NIST CAVP/FIPS in the US, GOST/FSB in Russia, KCMVP in South Korea, OSCCA's SM-series in China, SOG-IS/EUCC and national lists in the EU, ASD's ISM in Australia) certify **primitives** and the **modules** built on them, not compositional schemes. Eligibility for regulated use is therefore inherited from the primitives ITB is configured with, not conferred by ITB itself.

The wrapper layer prefixes a fresh CSPRNG nonce and XORs every byte of an ITB ciphertext under one of outer keystream ciphers, one per PRF-grade ITB registry primitive in CTR mode. The keystream construction is delegated libitb-side to the `ctr` package. The wire format becomes `nonce || keystream-XOR(bytestream)`, indistinguishable from any generic stream-cipher payload by surface pattern; ITB's own content-deniability is unchanged.

The numbers below isolate the **outer cipher cost** that the wrapper layer adds on top of ITB. Two test scopes:

* **Wrapper Only** — 16 MiB random buffer, no ITB call. Pure outer cipher round-trip throughput. The `WrapInPlace` row mutates the caller's buffer (no output-buffer allocation); the `Wrap` row allocates a fresh output buffer per call.
* **Full ITB + wrapper** — encrypt and decrypt are timed **separately** (split sub-benches `…/encrypt` and `…/decrypt`) so the per-direction breakdown is visible. Both Single Ouroboros and Triple Ouroboros are reported. Single-message benches process a 16 MiB plaintext under one encrypt / wrap call (or one unwrap / decrypt call). Streaming benches process a 64 MiB plaintext through 16 MiB chunks via either ITB's callback-driven Streaming AEAD API or a User-Driven Loop emitting framed chunks through the wrap-stream writer.

The wrapper bench covers all outer ciphers — each in CTR mode.

### Concurrency note — outer cipher throughput on big-iron

Outer-cipher overhead on a 16 HT host with hardware AES-NI is effectively zero — the AES-CTR keystream finishes well ahead of every ITB-encrypt slot, and the `WrapInPlace` path avoids output-buffer allocation. **On larger Triple Ouroboros hosts (e.g. AMD EPYC 9655P, 192 HT) the picture inverts for the non-AES outer ciphers**: ITB's per-pixel hashing scales across all available HT, while the wrapper's keystream XOR splits across up to 32 worker goroutines (`min(32, GOMAXPROCS, chunks)`) inside libitb for buffers at or above the 256 KiB threshold, each worker seeking its own keystream to its chunk offset via `ctr.NewAt`; buffers below the threshold run serially.

The Fortran binding routes XOR through a single libitb FFI call; the parallelisation across up to 32 goroutines happens inside libitb for buffers at or above the 256 KiB threshold, so the binding adds only per-call FFI-crossing overhead on top of the parallel XOR.

### Compiler note — gfortran is the reference baseline

The Fortran binding ships under both gfortran (default) and ifx (Intel oneAPI). gfortran is the canonical reference for the BENCH.md tables — every cell below is measured under gfortran's per-FFI-call cost profile. ifx measures roughly **15–48% slower** than gfortran on the existing bench surfaces (see `bench/BENCH.md` for the gfortran-vs-ifx comparison). The wrapper bench surface inherits the same compiler asymmetry; reproduction with ifx requires `make FC=ifx bench` and the `-heap-arrays 0` flag the Makefile auto-applies under ifx.

## Binding asymmetry note

The Fortran binding's Streaming No MAC arm covers the User-Driven Loop variant only — there is no IO-Driven Streaming No MAC writer / reader pair. The Streaming AEAD path covers IO-Driven for both Easy and Low-Level.

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

## Configuration

* Outer cipher path: all PRF-grade registry primitives, keystream built libitb-side via the `ctr` package.
* ITB primitive: Areion-SoEM-512.
* ITB seed width: 1024 bits.
* ITB cipher config: `NonceBits=128`, `BarrierFill=1`, `BitSoup=0`, `LockSoup=0` (minimum config so the outer cipher delta is not masked by per-pixel feature cost).
* `itb_set_max_workers(0)` (use every available HT for the per-pixel hash kernels).
* MAC factory: HMAC-BLAKE3, 32-byte CSPRNG key (where applicable).
* Single-message plaintext: 16 MiB random.
* Streaming plaintext: 64 MiB random; chunk size 16 MiB.
* Decrypt-only sub-benches refresh the working wire from a pristine copy each iteration via array assignment; the copy is included in the timed total. This overhead is small relative to ITB's Decrypt cost on this hardware.
* Compiler: gfortran (default; `-O2`). ifx alternative (`make FC=ifx bench`) measures 15–48% slower.

Column abbreviations in the Full ITB + wrapper tables: **LL** = Low-Level, **Loop** = User-Driven Loop, **IO** = IO-Driven, **NoMAC** = No MAC, **MAC** = MAC Authenticated, **Enc** / **Dec** = encrypt / decrypt direction. All throughput is MB/s, rounded.

### Wrapper only round-trip (16 MiB plaintext, encrypt + decrypt timed together)

| Outer cipher | `Wrap` (alloc) MB/s | `WrapInPlace` (no output-buffer alloc) MB/s |
|---|---|---|
| **Areion-SoEM-256** | 936 | 1878 |
| **Areion-SoEM-512** | 953 | 1899 |
| **BLAKE2b-256** | 623 | 941 |
| **BLAKE2b-512** | 774 | 1366 |
| **BLAKE2s** | 639 | 998 |
| **BLAKE3** | 820 | 1506 |
| **AES-128-CTR** | 1094 | 2828 |
| **SipHash-2-4** | 1006 | 2136 |
| **ChaCha20** | 964 | 2052 |

### Single Message — Single Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 154 | 234 | 163 | 221 | 175 | 245 | 165 | 227 |
| **Areion-SoEM-512** | 177 | 243 | 151 | 224 | 178 | 245 | 163 | 227 |
| **BLAKE2b-256** | 159 | 212 | 150 | 200 | 160 | 210 | 150 | 200 |
| **BLAKE2b-512** | 171 | 231 | 160 | 216 | 167 | 232 | 159 | 217 |
| **BLAKE2s** | 162 | 216 | 152 | 202 | 162 | 217 | 152 | 202 |
| **BLAKE3** | 173 | 235 | 161 | 220 | 174 | 237 | 161 | 219 |
| **AES-128-CTR** | 183 | 254 | 169 | 234 | 182 | 255 | 170 | 235 |
| **SipHash-2-4** | 180 | 247 | 164 | 230 | 179 | 244 | 167 | 230 |
| **ChaCha20** | 175 | 248 | 165 | 229 | 179 | 247 | 166 | 230 |

### Single Message — Triple Ouroboros (16 MiB plaintext)

| Cipher | Easy NoMAC Enc | Easy NoMAC Dec | Easy MAC Enc | Easy MAC Dec | LL NoMAC Enc | LL NoMAC Dec | LL MAC Enc | LL MAC Dec |
|---|---|---|---|---|---|---|---|---|
| **Areion-SoEM-256** | 231 | 269 | 204 | 249 | 233 | 268 | 203 | 250 |
| **Areion-SoEM-512** | 232 | 267 | 210 | 251 | 233 | 268 | 211 | 253 |
| **BLAKE2b-256** | 203 | 229 | 185 | 217 | 204 | 229 | 187 | 219 |
| **BLAKE2b-512** | 219 | 252 | 200 | 238 | 220 | 249 | 201 | 239 |
| **BLAKE2s** | 204 | 233 | 188 | 220 | 205 | 233 | 190 | 222 |
| **BLAKE3** | 223 | 253 | 204 | 243 | 225 | 258 | 204 | 244 |
| **AES-128-CTR** | 240 | 280 | 219 | 263 | 242 | 282 | 220 | 265 |
| **SipHash-2-4** | 236 | 271 | 213 | 256 | 236 | 272 | 214 | 259 |
| **ChaCha20** | 232 | 271 | 212 | 255 | 234 | 273 | 214 | 256 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 164 | 226 | 165 | 226 |
| **Areion-SoEM-512** | 164 | 226 | 165 | 226 |
| **BLAKE2b-256** | 152 | 201 | 151 | 201 |
| **BLAKE2b-512** | 159 | 215 | 158 | 218 |
| **BLAKE2s** | 152 | 203 | 152 | 203 |
| **BLAKE3** | 161 | 218 | 162 | 222 |
| **AES-128-CTR** | 169 | 234 | 169 | 236 |
| **SipHash-2-4** | 166 | 228 | 167 | 231 |
| **ChaCha20** | 165 | 228 | 167 | 230 |

### Streaming — Single Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 177 | 243 | 178 | 244 |
| **Areion-SoEM-512** | 177 | 243 | 178 | 243 |
| **BLAKE2b-256** | 161 | 212 | 161 | 213 |
| **BLAKE2b-512** | 170 | 230 | 171 | 233 |
| **BLAKE2s** | 162 | 216 | 162 | 215 |
| **BLAKE3** | 174 | 236 | 173 | 238 |
| **AES-128-CTR** | 183 | 253 | 182 | 255 |
| **SipHash-2-4** | 179 | 249 | 178 | 248 |
| **ChaCha20** | 179 | 247 | 178 | 248 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — AEAD

| Cipher | AEAD Easy IO Enc | AEAD Easy IO Dec | AEAD LL IO Enc | AEAD LL IO Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 203 | 246 | 210 | 251 |
| **Areion-SoEM-512** | 209 | 249 | 210 | 250 |
| **BLAKE2b-256** | 185 | 216 | 186 | 216 |
| **BLAKE2b-512** | 200 | 235 | 200 | 237 |
| **BLAKE2s** | 187 | 219 | 185 | 220 |
| **BLAKE3** | 204 | 241 | 205 | 242 |
| **AES-128-CTR** | 218 | 262 | 219 | 264 |
| **SipHash-2-4** | 212 | 254 | 214 | 256 |
| **ChaCha20** | 212 | 253 | 214 | 256 |

### Streaming — Triple Ouroboros (64 MiB plaintext, 16 MiB chunk size) — Non-AEAD (User-Driven Loop)

| Cipher | Easy Loop Enc | Easy Loop Dec | LL Loop Enc | LL Loop Dec |
|---|---|---|---|---|
| **Areion-SoEM-256** | 230 | 260 | 229 | 263 |
| **Areion-SoEM-512** | 230 | 262 | 230 | 264 |
| **BLAKE2b-256** | 202 | 227 | 199 | 226 |
| **BLAKE2b-512** | 218 | 248 | 217 | 248 |
| **BLAKE2s** | 205 | 230 | 203 | 231 |
| **BLAKE3** | 222 | 253 | 222 | 256 |
| **AES-128-CTR** | 240 | 277 | 240 | 279 |
| **SipHash-2-4** | 233 | 270 | 234 | 270 |
| **ChaCha20** | 232 | 269 | 234 | 270 |

This file is updated by re-running the reproduction command and pasting the bench output into the tables. Numbers above are rounded to MB/s.
