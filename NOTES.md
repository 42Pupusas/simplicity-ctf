# Simplicity CTF — working notes

Reward: **0.01 L-BTC** locked behind two cooperating Simplicity contracts.
Funding tx: `aa52a138a0e193c8530e1195b201c7139de194decc0ff3bb01489adbe814095c` (Liquid, block 3958294).

## On-chain state (funding tx outputs)

The tx **issues asset** `6e49cd6ef8acd9e2fe5e59a34fbc8ab4db81c6d6aaf30f2d240d77e84cc3b739`
(the "asset_lock" / AUTH asset), `assetamount = 12`, non-blinded.

| vout | value | asset | scriptPubKey (v1 p2tr x-only key) | role |
|------|-------|-------|-----------------------------------|------|
| 0  | 1 | AUTH  | `481c09e61276c6fae6bdd92b6df2c9943a94e9ea373a585605cf1ec602478192` | auth token slot |
| 1  | 1 | AUTH  | `c5b2b6d0930d64caf4f5e1ac75e7554784fe54dbcc0389e3e1201a0b26f0490d` | auth token slot |
| 2..10 | 1 each | AUTH | 9 more p2tr slots | auth token slots |
| 11 | 1 | AUTH  | `85e529ae669ae2aba9f4fa77b0dd0236822f5d1238c463cb5b51ef8907e85d43` | auth token slot |
| 12 | 1_000_000 | L-BTC | `9250938b6e2af7b410b110c3886c933e216c75f5a6e67639af0a75d5542d45c2` | **0.01 L-BTC reward** |
| 13 | 0 | — | OP_RETURN `e2d2636e…696573` | datum |
| 14 | — | L-BTC | change (blinded p2wpkh) | change |
| 15 | 137 | L-BTC | fee | fee |

12 AUTH tokens of value 1 spread across outputs 0..11. The reward sits on output 12.

## Contracts

### `ctf.simf` — the reward gate
`withdraw_rewards(sig)`:
1. `assert current_index() == 0`  → this contract must be spent as **input 0**.
2. `bip_0340_verify(OWNER_PUBKEY, sig_all_hash(), sig)`.
3. read `output_amount(0)` → `(asset, amount)`.
4. `assert asset == AUTH_ASSET_ID` and `assert amount == 12`.

So a spend of the reward is only valid if **output 0 of the spending tx pays exactly 12
units of the AUTH asset**, and a valid OWNER signature over SIGHASH_ALL is presented.

### `asset_lock.simf` — the auth-token covenant
`unlock(sig, nonce)`:
1. `bip_0340_verify(OWNER_PUBKEY, sig_all_hash(), sig)`.
2. `assert current_script_hash() == get_script_hash_for_storage(nonce)`.

`get_script_hash_for_storage(nonce)` rebuilds a p2tr scriptPubKey:
- `nonce_slot_leaf = sha256( tapdata_init || (0u64,0,0,nonce) )`   (a "storage slot" leaf)
- `tap_node = build_tapbranch(tapleaf_hash(), nonce_slot_leaf)`
- `tweaked = build_taptweak(H, tap_node)` where `H = 50929b74…803ac0` is the
  **BIP-341 NUMS unspendable point**.
- scripthash = `sha256(0x5120 || tweaked)`  (segwit v1, 32-byte push).

i.e. each AUTH slot is a taproot output whose merkle tree is `{ this Simplicity leaf,
a data leaf committing to `nonce` }`, internal key = NUMS. It's a covenant that pins the
token to a self-referential address parameterised by `nonce` (a storage-array index).

## Unknowns we control (compile-time `param::` arguments)
`OWNER_PUBKEY` and `AUTH_ASSET_ID` are **not** in the repo — they are Simplex `Arguments`
supplied by the solver (`CtfArguments`, `AssetLockArguments` in `tests/your_solution.rs`).
`AUTH_ASSET_ID` is forced: it must equal `6e49cd…b739` for the CMR/address to match on-chain.
`OWNER_PUBKEY` must be whatever the challenge author committed (the address on-chain fixes it).

## AUTHOR HINTS (decisive — the bug is covenant logic, NOT a leaked key)
1. Underconstrained witness: asset_lock's `nonce` is `witness::NONCE`, attacker-chosen and
   UNSIGNED. Everything derived from it (storage slot / scriptHash) is attacker-malleable.
2. Transaction topology: `ctf` pins `current_index()==0` and inspects `output_amount(0)`.
   `asset_lock` pins NO index — it never constrains where it sits nor where its value goes.
3. Signature replay: both verify `bip_0340_verify((OWNER_PUBKEY, sig_all_hash()), sig)`.
   `sig_all_hash()` is the SIGHASH_ALL digest over the WHOLE tx — identical for every input
   in that tx. So ONE owner signature satisfies every input, and a sig captured from any
   prior owner spend can be replayed into a new tx that reproduces the signed digest.

## Refined theory: single-tx drain
Build ONE tx that: spends the ctf reward UTXO (vout12) as INPUT 0 (satisfies
`current_index()==0`); spends all 12 asset_lock token UTXOs (vout0..11) as inputs 1..12;
pays all 12 AUTH units into OUTPUT 0 (satisfies ctf's `output_amount(0)==12 AUTH`); sends
the L-BTC reward to us in another output. Every input verifies the SAME `sig_all_hash()`
against the SAME OWNER_PUBKEY, so a single owner signature (via replay) unlocks all inputs.
asset_lock never constrains its index/destination, so nothing stops re-routing tokens into
ctf output 0 and the reward to us. EXPERIMENT: confirm `sig_all_hash()` is index-independent
here (that is what makes single-sig replay valid).

## CONFIRMED THIS SESSION (in-sandbox `cargo test`, no simplex needed)
- OWNER_PUBKEY = OP_RETURN datum `e2d2636e…696573`; ctf reconstruction reproduces vout-12
  key `9250938b…45c2` with LITTLE-ENDIAN AUTH asset id. Works on mainnet AND regtest (the
  32-byte taproot key is network-independent). No simplex harness needed to reconstruct addrs.
- `sig_all_hash = SHA256(genesis‖genesis‖txHash‖tapEnvHash‖ix)` (simplicity-sys txEnv.c) —
  commits to input index AND leaf CMR. So my earlier "one sig covers all inputs" theory is
  WRONG; sigs are index+contract bound. Also: no owner Schnorr sig exists anywhere on-chain
  (parent tx is ECDSA P2WPKH; covenant UTXOs unspent), so nothing to replay yet.
- asset_lock reconstruction is structurally sound (owner binds CMR; primitives verified:
  tapdata_init tag="TapData" == SDK tap_data_hash; make_tapbranch tag="TapBranch/elements",
  lexicographic sort; internal key = NUMS H; nonce serializes as 32-byte BE of the u64).
- NEGATIVE: no on-chain token (vout0..11) matches nonce ∈ 0..4096, nor BIP39 word-index,
  nor ASCII-packed word (first 24 words, right/left BE), nor owners {op_return, funding xonly,
  NUMS, contract_hash, zero} at small nonce. ⇒ the 12 nonces are LARGE non-sequential u64s.

## LEADING THEORY (user): 12 tokens encode a 12-word BIP39 mnemonic → owner privkey.
  Each token nonce is a u64; a BIP39 word (≤8 ascii) fits exactly in 8 bytes = one u64.
  NEXT: embed the full 2048-word BIP39 list; compute asset_lock tapleaf CMR once, then pure
  Rust build_tapbranch/build_taptweak per (word × packing) → decode all 12 slots instantly.
  This is a dictionary decode of a known commitment, NOT a 256-bit brute force.

## ==================== SOLVED ✅ OWNER KEY RECOVERED ====================
# MNEMONIC (vout order, BIP39 checksum VALID): "hole art knife walnut language cool borrow
#   board rival silk october boy"
# DERIVATION: seed -> m/84'/1776'/0'/0/0 -> x-only pubkey == e2d2636e… (OWNER_PUBKEY) ✅
# OWNER PRIVKEY = 476f8dcb2d92a8ac9d5962b02e68dc445553f98a56cdf24c71aa5a742c68bf5b
# Remaining: build drain tx in `solution` (runs under `simplex test`): input0=ctf reward vout12,
#   inputs1..12=tokens (witness NONCE = left_be(word) per token), output0=12 AUTH, output1=reward
#   to us; sign each input with owner key over ITS OWN sig_all_hash (index+CMR bound).

## ================= MNEMONIC DECODED (12/12 tokens) =================
# nonce = word ASCII bytes, BIG-ENDIAN, LEFT-aligned in u64 ("left_be"): e.g. "hole" ->
# 0x686f6c6500000000. Decoded via fast_asset_lock_key over the 2048 BIP39 words (tests/
# bip39_english.txt). vout->word:
#   0 hole  1 art  2 knife  3 walnut  4 language  5 cool
#   6 borrow 7 board 8 rival 9 silk 10 october 11 boy
# MNEMONIC (vout order): "hole art knife walnut language cool borrow board rival silk october boy"
# NEXT: validate BIP39 checksum; derive owner privkey (try paths m/84'/1776'/0'/0/0, m/86'..,
# BIP340 x-only) and check pubkey == e2d2636e… (OWNER_PUBKEY). Then build drain tx & sign each
# input over its own sig_all_hash. Note: word ORDER within the mnemonic may not be vout order —
# if checksum fails, the 12 words may need reordering (only known order is vout index).

## STATUS: fast_asset_lock_key VALIDATED (== SDK for nonce 0,5,42,1000), pure-Rust, no per-call
#  recompile. But secp tweak still ~us/call => blind linear u64 sweep hopeless (5M in >5min, 0
#  hits). Word-INDEX (0..2047) ruled out. Need to KNOW what the nonces are, not brute them.
#  NEXT IDEAS: (a) full BIP39 2048-word ascii packings (le/be, len-prefixed) via fast recon;
#  (b) reconsider if spending tokens is even required — ctf only needs output0=12 AUTH units,
#     maybe AUTH can be moved without satisfying all 12 asset_lock covenants; (c) inspect how
#  smplx-sdk random_mnemonic / word->nonce mapping works (bip39::Mnemonic, 12 words).
#  File tests/your_solution.rs REWRITTEN CLEAN (10KB): probe_ctf_vout12, probe_fast_recon_valid,
#  decode_nonces_fast(#ignore), solution skeleton. Compiles+passes. hex/base64/bip39 deps GONE.

## FAST RECON (validated model, code was cruft-blocked): asset_lock p2tr key =
#   leaf = CompiledProgram::new_with_unstable(ASSET_LOCK.SOURCE, UnstableFeatures::all(),
#          AssetLockArguments{owner}.build_arguments(), include_debug=TRUE, ElementsJetHinter)
#          .commit().cmr()  -> Script::from(cmr.to_vec()); leafVersion = simplicity::leaf_version()
#   hidden = sha256(sha256("TapData")||sha256("TapData")||slot)  [= SDK tap_data_hash]
#   TaprootBuilder::new().add_leaf_with_ver(1,leaf,ver).add_hidden(1,hidden)
#          .finalize(SECP256K1, NUMS 50929b74…).output_key().into_inner().serialize()
#   slot for nonce = BE32(nonce) (nonce in low 8 bytes). Word-INDEX (0..2047) ruled out (0/12).
# TODO: word-index dead => sweep large nonce space fast with above pure-Rust (one compile),
#   OR test ascii-packed BIP39 words (full 2048 list). SDK uses bip39::Mnemonic (12 words).
# WARNING: tests/your_solution.rs bloated to 1194 lines of stale cruft (bip39/base64/dup fns) —
#   compiler sees stale copies; NEEDS CLEAN REWRITE keeping only: consts, hex helpers,
#   ctf_key/asset_lock_key, fast_asset_lock_key, asset_lock_leaf_script, set_global_config(Debug).

## ============ BREAKTHROUGH: DEBUG SYMBOLS CHANGE THE CMR ============
- `GlobalConfig::set_global_config(Verbosity::Debug)` (what `simplex test` uses) => debug
  symbols ON => DIFFERENT CMR => DIFFERENT address. Plain `cargo test` defaults to None/OFF.
- WITH Debug on: CtfProgram(owner=op_return e2d2636e…, auth=LE of 6e49cd…b739), NUMS internal
  key => ctf address = 9250938b…45c2 == vout12 EXACT MATCH. ✅
  So OWNER_PUBKEY=op_return (BE), AUTH_ASSET_ID=asset LE. My old "debug symbols irrelevant"
  note was WRONG — that mismatch is why EVERY reconstruction/nonce sweep failed for weeks.
- ACTION for ALL address work: call set_global_config(Verbosity::Debug) FIRST (once per proc).
- asset_lock reconstruction now correct too; nonce 0..3 don't hit vout0 (nonces are large).
  Per-call SDK compile is slow (~ms) => 100k linear sweep times out. NEXT: cache asset_lock
  tapleaf CMR once (one compile), then pure-Rust tap_data_hash(BE32(nonce)) + build_tapbranch
  (lexicographic, tag TapBranch/elements) + build_taptweak(NUMS) + p2tr to sweep fast, OR test
  BIP39-word-index / word-ascii-packing nonces directly. Then decode 12 nonces -> mnemonic ->
  owner privkey -> sign each input's sig_all_hash -> drain.

## !!! PRIOR "CONFIRMED" FACT WAS FALSE (corrected this session) !!!
- ctf reconstruction does NOT reproduce vout12. CtfProgram(owner=op_return, auth=LE) with NUMS
  internal key => `dee26d6b…`, NOT `9250938b…`. Owner-as-internal-key => `7e6cc251…`. A full
  sweep of owner∈{op_be,op_le,zero} × auth∈{be,le,sha,zero} matched vout12 for NO combo.
  => I currently CANNOT reproduce any on-chain address (ctf OR asset_lock) from the .simf.
  Every downstream nonce/seed/key theory rested on this false premise. START OVER on mapping.
- Likely causes: (a) compiled ctf.simf != the source that made the on-chain addr (param values
  differ), (b) wrong Arguments->param mapping / storage, or (c) vout12 is a plain owner P2TR,
  not the covenant. NEXT: verify against smplx-std's OWN taproot_spending_info test vectors to
  pin the exact tree/tweak the SDK builds, then re-derive what params yield 9250938b….

## GROUND TRUTH from funding tx aa52a138 (blockstream liquid api, fetched)
- vin0 prevout = 68a40711:1, P2WPKH `0014f72a0d…`, addr ex1q7u4q6…, signed by key `026ace88…`
  (ECDSA r=1be401e3…). ISSUANCE here: asset_id 6e49cd…b739, contract_hash
  `f294856522edcbfc6cf6cd605d9ffa8e13f7c7d6157ed4f3c04d74f973206422`,
  asset_entropy `e3aaf335cf888e5a664ed25f86c30be3383d117b007d5079b1c2658ef743b1cf`, amount 12.
- vout0..11 = 12x v1_p2tr, value 1, asset 6e49cd…b739 (AUTH tokens, freshly minted here).
- vout12 = v1_p2tr key 9250938b…45c2, value 1000000, asset 6f0279e9ed041c3d710a9f57d0c02928
  416460c4b722ae3457a11eec381c526d (= L-BTC). This is the ctf reward.
- vout13 = OP_RETURN 32 bytes e2d2636e…696573 (OWNER_PUBKEY, VALID x-only point).
- vout14 = P2WPKH change back to ex1q7u4q6… (same wallet). vout15 = fee 137.
=> tokens/reward are self-contained in THIS tx. No owner Schnorr sig anywhere; sig gate is real
   & unforgeable; sigAllHash binds ix+CMR (no replay). So private key must derive from tx data.

## KEY CANDIDATES for owner privkey (self-contained): contract_hash f2948565…, asset_entropy
   e3aaf335…, funding wallet key 026ace88… / its ECDSA nonce, or fn(12 nonces). Owner pubkey
   e2d2636e… lets us VERIFY any candidate. asset_lock addr reconstruction still unsolved
   (no small-nonce/model match for vout0), so can't read nonces yet.

## Attack surface / hypotheses to test
Both paths gate on a Schnorr sig from `OWNER_PUBKEY` over `sig_all_hash()`. The interesting
questions:
1. **Is OWNER_PUBKEY actually the NUMS point / a known/degenerate key?** If the author reused
   the NUMS `H` (or a nothing-up-my-sleeve key with known discrete log, or a point whose
   parity/x makes BIP340 verify trivially satisfiable) then no secret is needed. Check the
   real x-only key committed in the tapleaf once artifacts are built.
2. **Signature replay.** `sig_all_hash()` is SIGHASH_ALL over the *proposed* tx. If a valid
   OWNER signature is already public (e.g. in a prior spend of an identical-shape tx, or the
   OP_RETURN datum in vout 13), a tx can be crafted whose sighash matches. Inspect
   `e2d2636e…696573`.
3. **"Cooperating" trick.** ctf requires output0 = 12 AUTH tokens + current_index 0.
   asset_lock requires each token spent from its slot address. A single tx that spends the
   ctf UTXO as input 0 AND consolidates all 12 AUTH tokens into output 0 satisfies *both*
   covenants simultaneously — the two contracts are meant to be unlocked in one tx. The crux
   remains producing the OWNER sig; the covenant shape itself is not the lock, the key is.
4. **NUMS internal-key spend of the reward (vout 12).** If `9250938b…45c2` was built by the
   *same* `get_script_hash_for_storage`-style construction, its merkle root is known, so the
   only barrier is the NUMS key-path (unspendable) vs the Simplicity leaf. Confirm whether
   vout12 is a ctf leaf or an asset_lock slot by matching CMRs after `simplex build`.

## Next steps
- `simplexup --install v0.0.8` then `simplex build` to generate `src/artifacts/` (the
  git-ignored Rust bindings: `CtfProgram`, `AssetLockProgram`, `*Arguments`, `*Witness`).
  Only then does `cargo build` / `simplex test -v` work.
- Recompute each contract's CMR and taproot output key for candidate `OWNER_PUBKEY` values
  and match against the 12 on-chain scriptPubKeys to (a) confirm OWNER_PUBKEY and (b) label
  every output as ctf-leaf vs asset_lock-slot(nonce).
- Build the witness (owner sig or the bypass from hypothesis 1/2) in `tests/your_solution.rs`
  and drive a spend to output0 = 12 AUTH tokens.
