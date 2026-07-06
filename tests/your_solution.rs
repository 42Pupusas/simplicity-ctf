//! Simplicity CTF — solution work-in-progress.
//!
//! Reward: 0.01 L-BTC (1_000_000 sats) at vout 12 of funding tx
//!   aa52a138a0e193c8530e1195b201c7139de194decc0ff3bb01489adbe814095c (Liquid mainnet).
//! Twelve AUTH tokens (asset 6e49cd…b739, value 1 each) at vout 0..11.
//!
//! ## KEY BREAKTHROUGH — debug symbols change the CMR
//! `simplex test` compiles at Debug verbosity ⇒ `include_debug_symbols = true` ⇒ a DIFFERENT
//! program CMR ⇒ a DIFFERENT taproot address than a plain `cargo test` (which defaults to
//! symbols OFF). Every reconstruction MUST first call
//! `GlobalConfig::set_global_config(Verbosity::Debug)`.
//!
//! With that set:
//! - `CtfProgram { owner_pubkey = op_return e2d2636e…, auth_asset_id = LE(6e49cd…b739) }`
//!   with the NUMS internal key reproduces vout-12 `9250938b…45c2` EXACTLY. ✅
//!   ⇒ OWNER_PUBKEY = op_return datum (big-endian); AUTH_ASSET_ID = issued asset id, LE.
//! - ABI (confirmed): ctf params {AUTH_ASSET_ID: u256, OWNER_PUBKEY: u256}, witness
//!   {SIGNATURE: [u8;64]}; asset_lock params {OWNER_PUBKEY: u256}, witness {SIGNATURE, NONCE}.
//!
//! ## SOLVED — owner key recovered
//! The 12 asset_lock nonces each encode a BIP39 word as ASCII bytes, LEFT-aligned big-endian in
//! the low u64 (slot value = BE32 with word bytes at offset 24). Decoded (vout order):
//!   hole art knife walnut language cool borrow board rival silk october boy
//! Valid BIP39 checksum. Derives OWNER_PUBKEY e2d2636e… at path m/84h/1776h/0h/0/0.
//! OWNER PRIVKEY = 476f8dcb2d92a8ac9d5962b02e68dc445553f98a56cdf24c71aa5a742c68bf5b
//!
//! ## (historical) decode the 12 token nonces
//! Each token (vout 0..11) is an `asset_lock` covenant whose hidden taproot slot commits to a
//! `nonce: u64` (slot value = BE32(nonce)). Word-index (0..2047) hypothesis is RULED OUT.
//! `fast_asset_lock_key` reconstructs a token address from the leaf CMR (compiled once) so we
//! can sweep quickly. Theory: the 12 nonces encode a 12-word BIP39 mnemonic → owner privkey.

use simplicity_ctf::artifacts::ctf::CtfProgram;
use simplicity_ctf::artifacts::ctf::derived_ctf::CtfArguments;
use simplicity_ctf::artifacts::asset_lock::AssetLockProgram;
use simplicity_ctf::artifacts::asset_lock::derived_asset_lock::AssetLockArguments;

use simplex::provider::SimplicityNetwork;

const AUTH_ASSET_ID: &str = "6e49cd6ef8acd9e2fe5e59a34fbc8ab4db81c6d6aaf30f2d240d77e84cc3b739";
const OWNER_OP_RETURN: &str = "e2d2636ee884d4e1137dfb15bdff1bc8df7c01812bc142c7323202237c696573";
const NUMS_KEY: &str = "50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

/// vout → on-chain x-only taproot output key. 0..=11 tokens, 12 = ctf reward.
const ONCHAIN_SPK_KEYS: [(u32, &str); 13] = [
    (0, "481c09e61276c6fae6bdd92b6df2c9943a94e9ea373a585605cf1ec602478192"),
    (1, "c5b2b6d0930d64caf4f5e1ac75e7554784fe54dbcc0389e3e1201a0b26f0490d"),
    (2, "2a2bc5d78b79dd5caa1b0428db86ab4c0c5db268bb612babbbb5b24a357e67c3"),
    (3, "a5044ac952e2b29940f13f61938a5b2345ac297d911deae4d2d8a21b98859bd5"),
    (4, "92755c5d873f7074dd2634eb980d316adff9c3ce15624fbab6deb425f0ec8f74"),
    (5, "2fe7c76967282f30c57eb9d430f569632517f4dd14517bafc623f97bcaf1997b"),
    (6, "917afd9db832bd1c86206f6e026646ae4e065591340abca3629cdaf0a20213d4"),
    (7, "6a300f0a8449f2265ac25e3e51b85b2da4c9765af30b88047f6419a4fb4370aa"),
    (8, "5a328847f2d4a16caf13c97a782ac1ae4f5d51d43b7b1ccfbc204bd59442da27"),
    (9, "cdcc8672237b11535c7875f6fc21f0433e2bc15c1f1932c441ca6fecde498655"),
    (10, "856c1dae118ae4b9ba61eb3d611d4761d69cb04d8764dc500933d2302dacbd61"),
    (11, "85e529ae669ae2aba9f4fa77b0dd0236822f5d1238c463cb5b51ef8907e85d43"),
    (12, "9250938b6e2af7b410b110c3886c933e216c75f5a6e67639af0a75d5542d45c2"),
];

// ─────────────────────────── helpers ───────────────────────────

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

fn hex32(s: &str) -> anyhow::Result<[u8; 32]> {
    anyhow::ensure!(s.len() == 64, "expected 64 hex chars, got {}", s.len());
    let mut out = [0u8; 32];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(chunk)?, 16)?;
    }
    Ok(out)
}

fn auth_asset_le() -> [u8; 32] {
    let mut a = hex32(AUTH_ASSET_ID).unwrap();
    a.reverse();
    a
}

/// Storage slot value asset_lock commits to for a nonce: BE32(nonce) (nonce in low 8 bytes).
fn nonce_slot_value(nonce: u64) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[24..].copy_from_slice(&nonce.to_be_bytes());
    v
}

fn strip_spk(spk_hex: &str) -> String {
    spk_hex.strip_prefix("5120").unwrap_or(spk_hex).to_string()
}

fn match_onchain(key: &str) -> Option<u32> {
    ONCHAIN_SPK_KEYS.iter().find(|(_, k)| *k == key).map(|(v, _)| *v)
}

fn enable_debug_symbols() {
    use simplex::global::{GlobalConfig, Verbosity};
    let _ = GlobalConfig::set_global_config(Verbosity::Debug);
}

fn ctf_key(owner: [u8; 32], auth: [u8; 32], net: &SimplicityNetwork) -> String {
    let ctf = CtfProgram::new(CtfArguments { owner_pubkey: owner, auth_asset_id: auth });
    strip_spk(&hex_encode(ctf.get_script_pubkey(net).as_bytes()))
}

/// SDK reconstruction of an asset_lock token address (authoritative but recompiles each call).
fn asset_lock_key(owner: [u8; 32], slot: Option<[u8; 32]>, net: &SimplicityNetwork) -> String {
    let mut al = AssetLockProgram::new(AssetLockArguments { owner_pubkey: owner });
    if let Some(v) = slot {
        al = al.with_storage_capacity(1);
        let _ = al.set_storage_at(0, v);
    }
    strip_spk(&hex_encode(al.get_script_pubkey(net).as_bytes()))
}

/// The asset_lock leaf script (= program CMR bytes), compiled ONCE with debug symbols on.
fn asset_lock_leaf_script(owner: [u8; 32]) -> anyhow::Result<simplex::simplicityhl::elements::Script> {
    use simplex::simplicityhl::{CompiledProgram, UnstableFeatures};
    use simplex::simplicityhl::ast::ElementsJetHinter;
    use simplex::simplicityhl::elements::Script;
    use simplex::program::ArgumentsTrait;
    let args = AssetLockArguments { owner_pubkey: owner };
    let compiled = CompiledProgram::new_with_unstable(
        AssetLockProgram::SOURCE,
        &UnstableFeatures::all(),
        args.build_arguments(),
        true, // include_debug_symbols — matches simplex test / on-chain CMR
        Box::new(ElementsJetHinter),
    )
    .map_err(|e| anyhow::anyhow!("compile: {e:?}"))?;
    let cmr = compiled.commit().cmr();
    Ok(Script::from(cmr.as_ref().to_vec()))
}

/// Fast pure-Rust asset_lock p2tr key from a precompiled leaf script + a storage slot.
fn fast_asset_lock_key(leaf_script: &simplex::simplicityhl::elements::Script, slot: [u8; 32]) -> String {
    use simplex::simplicityhl::elements::taproot::TaprootBuilder;
    use simplex::simplicityhl::simplicity::leaf_version;
    use simplex::simplicityhl::elements::bitcoin::secp256k1::SECP256K1;
    use simplex::simplicityhl::simplicity::hashes::{sha256, Hash, HashEngine as _};

    let tag = sha256::Hash::hash(b"TapData");
    let mut eng = sha256::Hash::engine();
    eng.input(tag.as_byte_array());
    eng.input(tag.as_byte_array());
    eng.input(&slot);
    let hidden = sha256::Hash::from_engine(eng);

    let nums = hex32(NUMS_KEY).unwrap();
    let internal = simplex::simplicityhl::elements::bitcoin::key::XOnlyPublicKey::from_slice(&nums).unwrap();

    let info = TaprootBuilder::new()
        .add_leaf_with_ver(1, leaf_script.clone(), leaf_version())
        .unwrap()
        .add_hidden(1, hidden)
        .unwrap()
        .finalize(SECP256K1, internal)
        .unwrap();
    hex_encode(&info.output_key().into_inner().serialize())
}

// ─────────────────────────── experiments ───────────────────────────

/// Confirm the ctf reward reconstruction (vout12) with debug symbols on.
#[test]
fn probe_ctf_vout12() -> anyhow::Result<()> {
    enable_debug_symbols();
    let net = SimplicityNetwork::Liquid;
    let owner = hex32(OWNER_OP_RETURN)?;
    let k = ctf_key(owner, auth_asset_le(), &net);
    let hit = k == ONCHAIN_SPK_KEYS[12].1;
    eprintln!("[ctf] reward key = {k} {}", if hit { "<<< vout12 MATCH ✅" } else { "MISMATCH" });
    anyhow::ensure!(hit, "ctf reconstruction must match vout12");
    Ok(())
}

/// Validate fast_asset_lock_key against the SDK for a few slots.
#[test]
fn probe_fast_recon_valid() -> anyhow::Result<()> {
    enable_debug_symbols();
    let net = SimplicityNetwork::Liquid;
    let owner = hex32(OWNER_OP_RETURN)?;
    let leaf = asset_lock_leaf_script(owner)?;
    let mut all_ok = true;
    for n in [0u64, 5, 42, 1000] {
        let sdk = asset_lock_key(owner, Some(nonce_slot_value(n)), &net);
        let fast = fast_asset_lock_key(&leaf, nonce_slot_value(n));
        let ok = sdk == fast;
        all_ok &= ok;
        eprintln!("[valid] nonce {n:5}: {} sdk={} fast={}", if ok { "OK " } else { "BAD" }, &sdk[..16], &fast[..16]);
    }
    anyhow::ensure!(all_ok, "fast reconstruction must equal the SDK");
    Ok(())
}

/// Fast sweep of a nonce range to decode token slots (uses fast_asset_lock_key).
#[test]
#[ignore = "run explicitly; range may be large"]
fn decode_nonces_fast() -> anyhow::Result<()> {
    enable_debug_symbols();
    let owner = hex32(OWNER_OP_RETURN)?;
    let leaf = asset_lock_leaf_script(owner)?;
    let start: u64 = std::env::var("NONCE_START").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let max: u64 = std::env::var("NONCE_MAX").ok().and_then(|s| s.parse().ok()).unwrap_or(5_000_000);
    let threads: u64 = std::env::var("NONCE_THREADS").ok().and_then(|s| s.parse().ok()).unwrap_or(8);
    eprintln!("[decode] sweeping {start}..{max} across {threads} threads");
    let leaf = std::sync::Arc::new(leaf);
    let found = std::sync::Arc::new(std::sync::Mutex::new(std::collections::BTreeMap::<u32,u64>::new()));
    let mut handles = Vec::new();
    for t in 0..threads {
        let leaf = leaf.clone();
        let found = found.clone();
        handles.push(std::thread::spawn(move || {
            let mut n = start + t;
            while n < max {
                let key = fast_asset_lock_key(&leaf, nonce_slot_value(n));
                if let Some(v) = match_onchain(&key) {
                    if v < 12 {
                        let mut f = found.lock().unwrap();
                        if f.insert(v, n).is_none() {
                            eprintln!("[decode] vout{v:2} <- nonce {n} (0x{n:x})");
                        }
                    }
                }
                n += threads;
            }
        }));
    }
    for h in handles { let _ = h.join(); }
    let decoded = found.lock().unwrap().clone();
    eprintln!("[decode] {}/12: {decoded:?}", decoded.len());
    Ok(())
}

/// Decode hypothesis: each token nonce = a BIP39 word's ASCII bytes packed into a u64.
/// Sweeps all 2048 words × several packings via the fast reconstructor.
#[test]
fn decode_word_ascii() -> anyhow::Result<()> {
    enable_debug_symbols();
    let owner = hex32(OWNER_OP_RETURN)?;
    let leaf = asset_lock_leaf_script(owner)?;
    let words: Vec<&str> = include_str!("bip39_english.txt").lines().filter(|l| !l.is_empty()).collect();
    anyhow::ensure!(words.len() == 2048, "wordlist must be 2048, got {}", words.len());

    // packings: fn(word bytes) -> nonce u64
    let packings: [(&str, fn(&[u8]) -> Option<u64>); 6] = [
        ("right_be", |w| (w.len()<=8).then(|| { let mut b=[0u8;8]; b[8-w.len()..].copy_from_slice(w); u64::from_be_bytes(b) })),
        ("left_be",  |w| (w.len()<=8).then(|| { let mut b=[0u8;8]; b[..w.len()].copy_from_slice(w); u64::from_be_bytes(b) })),
        ("right_le", |w| (w.len()<=8).then(|| { let mut b=[0u8;8]; b[8-w.len()..].copy_from_slice(w); u64::from_le_bytes(b) })),
        ("left_le",  |w| (w.len()<=8).then(|| { let mut b=[0u8;8]; b[..w.len()].copy_from_slice(w); u64::from_le_bytes(b) })),
        ("first8_be",|w| { let n=w.len().min(8); let mut b=[0u8;8]; b[..n].copy_from_slice(&w[..n]); Some(u64::from_be_bytes(b)) }),
        ("first8_le",|w| { let n=w.len().min(8); let mut b=[0u8;8]; b[..n].copy_from_slice(&w[..n]); Some(u64::from_le_bytes(b)) }),
    ];

    let mut decoded: std::collections::BTreeMap<u32, (String, String)> = std::collections::BTreeMap::new();
    for (pname, pack) in packings {
        for (wi, w) in words.iter().enumerate() {
            if let Some(nonce) = pack(w.as_bytes()) {
                let key = fast_asset_lock_key(&leaf, nonce_slot_value(nonce));
                if let Some(v) = match_onchain(&key) {
                    if v < 12 {
                        eprintln!("[wascii] vout{v:2} <- word[{wi}]={w:?} packing={pname} nonce={nonce:#x}");
                        decoded.entry(v).or_insert((w.to_string(), pname.to_string()));
                    }
                }
            }
        }
    }
    eprintln!("[wascii] {}/12 tokens decoded", decoded.len());
    if decoded.len() == 12 {
        let phrase: Vec<String> = (0..12).map(|v| decoded[&v].0.clone()).collect();
        eprintln!("[wascii] MNEMONIC = {}", phrase.join(" "));
    }
    Ok(())
}

/// The decoded mnemonic (vout order). Validate BIP39 + derive owner privkey for e2d2636e….
const MNEMONIC_VOUT_ORDER: &str =
    "hole art knife walnut language cool borrow board rival silk october boy";

#[test]
fn derive_owner_key() -> anyhow::Result<()> {
    use simplex::simplicityhl::simplicity::bitcoin::bip32::{DerivationPath, Xpriv};
    use simplex::simplicityhl::simplicity::bitcoin::Network;
    use simplex::simplicityhl::simplicity::bitcoin::secp256k1::Secp256k1;
    use std::str::FromStr;

    let target = hex32(OWNER_OP_RETURN)?;
    let secp = Secp256k1::new();

    let mnemonic = bip39::Mnemonic::parse_normalized(MNEMONIC_VOUT_ORDER);
    match &mnemonic {
        Ok(_) => eprintln!("[derive] BIP39 checksum VALID for vout-order phrase ✅"),
        Err(e) => eprintln!("[derive] vout-order phrase invalid BIP39: {e} (may need reordering)"),
    }
    let mnemonic = mnemonic?;
    let seed = mnemonic.to_seed("");
    let master = Xpriv::new_master(Network::Bitcoin, &seed)?;

    let paths = [
        "m/84'/1776'/0'/0/0", "m/86'/1776'/0'/0/0", "m/84'/0'/0'/0/0",
        "m/86'/0'/0'/0/0", "m/44'/0'/0'/0/0", "m/0", "m",
    ];
    for p in paths {
        let path = DerivationPath::from_str(p)?;
        let child = master.derive_priv(&secp, &path)?;
        let (xpk, _) = child.private_key.x_only_public_key(&secp);
        let hit = xpk.serialize() == target;
        eprintln!("[derive] {p:22} -> {}{}", hex_encode(&xpk.serialize()), if hit { "  <<< OWNER MATCH ✅" } else { "" });
        if hit {
            eprintln!("[derive] OWNER PRIVKEY = {}", hex_encode(&child.private_key.secret_bytes()));
        }
    }
    Ok(())
}

/// Full BIP39 wordlist ASCII-packing sweep: each nonce may be a word's ASCII bytes packed into
/// a u64. Test all 2048 words x packings x 12 slots. A hit proves the mnemonic-encoding theory.
#[test]
fn decode_words_full() -> anyhow::Result<()> {
    enable_debug_symbols();
    let owner = hex32(OWNER_OP_RETURN)?;
    let leaf = asset_lock_leaf_script(owner)?;

    // Precompute all on-chain token keys -> vout.
    let words = bip39::Language::English.word_list();

    // Candidate u64 packings of a word's ASCII bytes (word len <= 8).
    type Pack = (&'static str, fn(&[u8]) -> Option<u64>);
    let packings: [Pack; 4] = [
        ("right_be", |w| { if w.len()>8 {return None;} let mut b=[0u8;8]; b[8-w.len()..].copy_from_slice(w); Some(u64::from_be_bytes(b)) }),
        ("left_be",  |w| { if w.len()>8 {return None;} let mut b=[0u8;8]; b[..w.len()].copy_from_slice(w); Some(u64::from_be_bytes(b)) }),
        ("right_le", |w| { if w.len()>8 {return None;} let mut b=[0u8;8]; b[8-w.len()..].copy_from_slice(w); Some(u64::from_le_bytes(b)) }),
        ("left_le",  |w| { if w.len()>8 {return None;} let mut b=[0u8;8]; b[..w.len()].copy_from_slice(w); Some(u64::from_le_bytes(b)) }),
    ];

    let mut hits = 0;
    for (pn, pack) in packings {
        for (wi, w) in words.iter().enumerate() {
            let Some(nonce) = pack(w.as_bytes()) else { continue; };
            let key = fast_asset_lock_key(&leaf, nonce_slot_value(nonce));
            if let Some(v) = match_onchain(&key) {
                eprintln!("[words] vout{v:2} <- word[{wi}] {w:?} packing={pn} nonce=0x{nonce:x}");
                hits += 1;
            }
        }
    }
    eprintln!("[words] {hits} hits across all packings");
    Ok(())
}

/// Decoded 12 words (vout order). Verify the mnemonic derives OWNER_PUBKEY e2d2636e… and print
/// the recovered private key. Tries vout-order + reverse, BIP39 valid checksum, common paths.
#[test]
fn recover_owner_key() -> anyhow::Result<()> {
    use bip39::Mnemonic;
    use simplex::simplicityhl::simplicity::bitcoin::bip32::{DerivationPath, Xpriv, Xpub};
    use simplex::simplicityhl::simplicity::bitcoin::Network;
    use simplex::simplicityhl::elements::secp256k1_zkp::Secp256k1;
    use std::str::FromStr;

    // vout -> word, from decode_words_full (left_be packing).
    let by_vout = [
        "hole","art","knife","walnut","language","cool",
        "borrow","board","rival","silk","october","boy",
    ];
    let target = hex32(OWNER_OP_RETURN)?;
    let secp = Secp256k1::new();

    let orders: [(&str, Vec<&str>); 2] = [
        ("vout_order", by_vout.to_vec()),
        ("reverse",    by_vout.iter().rev().copied().collect()),
    ];
    let paths = [
        "m","m/0","m/0h","m/0/0","m/0h/0/0","m/44h/0h/0h/0/0",
        "m/84h/0h/0h/0/0","m/84h/1776h/0h/0/0","m/44h/1776h/0h/0/0","m/86h/0h/0h/0/0",
    ];

    for (label, words) in &orders {
        let phrase = words.join(" ");
        match Mnemonic::parse(&phrase) {
            Ok(m) => {
                eprintln!("[recover] {label}: VALID bip39 checksum: {phrase}");
                let seed = m.to_seed("");
                let master = Xpriv::new_master(Network::Bitcoin, &seed)?;
                for p in paths {
                    let path = DerivationPath::from_str(p)?;
                    let d = master.derive_priv(&secp, &path)?;
                    let xpub = Xpub::from_priv(&secp, &d);
                    let xonly = xpub.public_key.x_only_public_key().0.serialize();
                    if xonly == target {
                        eprintln!("[recover] *** MATCH *** order={label} path={p} privkey={}", hex_encode(&d.private_key.secret_bytes()));
                        return Ok(());
                    }
                }
            }
            Err(e) => eprintln!("[recover] {label}: not a valid bip39 phrase: {e}"),
        }
    }
    eprintln!("[recover] no derivation matched OWNER_PUBKEY at tried orders/paths");
    Ok(())
}

// ─────────────────────────── solution (runs under simplex) ───────────────────────────

#[simplex::test]
fn solution(context: simplex::TestContext) -> anyhow::Result<()> {
    let _network = context.get_network();
    // Drain plan once owner key is recovered:
    //   input  0      = ctf reward vout12   → current_index()==0
    //   inputs 1..=12 = asset_lock tokens   → asset_lock never checks its index
    //   output 0      = 12 AUTH units       → ctf output_amount(0)==12
    //   output 1      = 1_000_000 sats L-BTC → us
    // Sign each input under OWNER_PUBKEY over its own sig_all_hash (index+CMR bound).
    Ok(())
}
