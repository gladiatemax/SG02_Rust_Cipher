//! Test d'integrazione: il binario cifra, la libreria thetacrypt decifra.
//!
//! Genera un gruppo SG02-Ed25519 (k=2, n=3), lancia `sg02-encrypt` come
//! processo esterno con la configurazione in ambiente, poi calcola k
//! decifrature parziali con le share private, le verifica e le aggrega.
//! E' lo stesso percorso di `thetacli dec` + `thetacli assemble`, senza
//! token: la compatibilita' con theta-app si verifica a parte, sul TCN.

use std::fs;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use theta_proto::scheme_types::{Group, ThresholdScheme};
use theta_schemes::interface::{Ciphertext, Serializable, ThresholdCipher, ThresholdCipherParams};
use theta_schemes::keys::key_generator::KeyGenerator;
use theta_schemes::keys::keys::PrivateKeyShare;
use theta_schemes::rand::{RngAlgorithm, RNG};

const BIN: &str = env!("CARGO_BIN_EXE_sg02-encrypt");

struct Fixture {
    dir: PathBuf,
    pubkey: PathBuf,
    shares: Vec<PrivateKeyShare>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn fixture(name: &str, scheme: ThresholdScheme, group: Group, k: usize, n: usize) -> Fixture {
    let dir = std::env::temp_dir().join(format!("sg02-encrypt-test-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();

    let mut rng = RNG::new(RngAlgorithm::OsRng);
    let shares = KeyGenerator::generate_keys(k, n, &mut rng, &scheme, &group, &None).unwrap();

    // Stesso contenuto del .pub scritto da `thetacli keygen`.
    let pubkey = dir.join("key.pub");
    fs::write(&pubkey, shares[0].get_public_key().to_bytes().unwrap()).unwrap();

    Fixture { dir, pubkey, shares }
}

fn run(env: &[(&str, &[u8])], stdin: &[u8]) -> Output {
    let mut cmd = Command::new(BIN);
    cmd.env_clear();
    for (k, v) in env {
        cmd.env(k, std::ffi::OsStr::from_bytes(v));
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Un processo che esce prima di leggere stdin chiude la pipe: l'errore
    // di scrittura qui e' atteso nei casi negativi.
    let _ = child.stdin.take().unwrap().write_all(stdin);
    child.wait_with_output().unwrap()
}

fn decrypt(ct_bytes: &[u8], f: &Fixture, which: &[usize]) -> Vec<u8> {
    let ct = Ciphertext::from_bytes(&ct_bytes.to_vec()).expect("crittogramma non deserializzabile");
    let pk = f.shares[0].get_public_key();
    assert!(ThresholdCipher::verify_ciphertext(&ct, &pk).unwrap());

    let mut params = ThresholdCipherParams::new();
    let mut partials = Vec::new();
    for &i in which {
        let share = ThresholdCipher::partial_decrypt(&ct, &f.shares[i], &mut params).unwrap();
        assert!(ThresholdCipher::verify_share(&share, &ct, &pk).unwrap(), "share {i} non valida");
        partials.push(share);
    }
    ThresholdCipher::assemble(&partials, &ct).expect("assemble fallito")
}

fn pk_env(f: &Fixture) -> Vec<u8> {
    f.pubkey.as_os_str().as_bytes().to_vec()
}

#[test]
fn roundtrip_with_any_k_shares() {
    let f = fixture("roundtrip", ThresholdScheme::Sg02, Group::Ed25519, 2, 3);
    let pk = pk_env(&f);
    let plaintext: Vec<u8> = (0..10_000u32).map(|i| (i * 31 + 7) as u8).collect();

    let out = run(&[("TCN_SG02_PUBKEY", &pk), ("TCN_SG02_LABEL", b"blocco-0001")], &plaintext);
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));

    let ct = Ciphertext::from_bytes(&out.stdout).unwrap();
    assert_eq!(ct.get_label(), b"blocco-0001");
    assert_eq!(ct.get_key_id(), f.shares[0].get_public_key().get_key_id());

    // Ogni sottoinsieme di k=2 share su n=3 deve decifrare.
    for subset in [[0, 1], [0, 2], [1, 2]] {
        assert_eq!(decrypt(&out.stdout, &f, &subset), plaintext);
    }
}

#[test]
fn label_bytes_are_preserved_exactly() {
    // Le variabili d'ambiente Unix sono byte arbitrari: la label non deve
    // passare per una conversione UTF-8.
    let f = fixture("label", ThresholdScheme::Sg02, Group::Ed25519, 2, 2);
    let label: &[u8] = &[0xff, 0x00 + 1, b'a', 0xc3];
    let out = run(&[("TCN_SG02_PUBKEY", &pk_env(&f)), ("TCN_SG02_LABEL", label)], b"x");
    assert_eq!(out.status.code(), Some(0), "stderr: {}", String::from_utf8_lossy(&out.stderr));
    let ct = Ciphertext::from_bytes(&out.stdout).unwrap();
    assert_eq!(ct.get_label(), label);
    assert_eq!(decrypt(&out.stdout, &f, &[0, 1]), b"x");
}

#[test]
fn ciphertexts_are_randomised() {
    let f = fixture("random", ThresholdScheme::Sg02, Group::Ed25519, 2, 2);
    let env: [(&str, &[u8]); 2] = [("TCN_SG02_PUBKEY", &pk_env(&f)), ("TCN_SG02_LABEL", b"L")];
    let a = run(&env, b"stesso plaintext");
    let b = run(&env, b"stesso plaintext");
    assert_eq!(a.status.code(), Some(0));
    assert_eq!(b.status.code(), Some(0));
    assert_ne!(a.stdout, b.stdout);
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let f = fixture("tamper", ThresholdScheme::Sg02, Group::Ed25519, 2, 2);
    let out = run(&[("TCN_SG02_PUBKEY", &pk_env(&f)), ("TCN_SG02_LABEL", b"L1")], b"segreto");
    assert_eq!(out.status.code(), Some(0));

    // Sostituire la label rompe la prova di validita' (e, f). I campi di
    // Sg02Ciphertext sono privati, quindi si altera direttamente il DER:
    // "L1" e "L2" hanno la stessa lunghezza, la struttura resta valida.
    let mut bytes = out.stdout.clone();
    let pos = bytes.windows(2).position(|w| w == b"L1").expect("label non trovata nel DER");
    bytes[pos + 1] = b'2';
    let forged = Ciphertext::from_bytes(&bytes).unwrap();
    assert_eq!(forged.get_label(), b"L2");
    assert!(!ThresholdCipher::verify_ciphertext(&forged, &f.shares[0].get_public_key()).unwrap());
}

fn expect_failure(out: &Output, code: i32, needle: &str) {
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(code), "stderr: {err}");
    assert!(err.contains(needle), "stderr senza '{needle}': {err}");
}

#[test]
fn missing_configuration() {
    let f = fixture("config", ThresholdScheme::Sg02, Group::Ed25519, 2, 2);
    let pk = pk_env(&f);
    expect_failure(&run(&[("TCN_SG02_LABEL", b"L")], b"x"), 2, "TCN_SG02_PUBKEY non impostata");
    expect_failure(&run(&[("TCN_SG02_PUBKEY", &pk)], b"x"), 2, "TCN_SG02_LABEL non impostata");
    expect_failure(&run(&[("TCN_SG02_PUBKEY", &pk), ("TCN_SG02_LABEL", b"")], b"x"), 2, "TCN_SG02_LABEL e' vuota");
    expect_failure(&run(&[("TCN_SG02_PUBKEY", &pk), ("TCN_SG02_LABEL", b"L")], b""), 2, "plaintext vuoto");
}

#[test]
fn bad_public_keys() {
    let f = fixture("badkey", ThresholdScheme::Sg02, Group::Ed25519, 2, 2);

    let missing = f.dir.join("assente.pub");
    expect_failure(
        &run(&[("TCN_SG02_PUBKEY", missing.as_os_str().as_bytes()), ("TCN_SG02_LABEL", b"L")], b"x"),
        3,
        "lettura",
    );

    let garbage = f.dir.join("garbage.pub");
    fs::write(&garbage, b"non e' una chiave").unwrap();
    let out = run(&[("TCN_SG02_PUBKEY", garbage.as_os_str().as_bytes()), ("TCN_SG02_LABEL", b"L")], b"x");
    assert_eq!(out.status.code(), Some(3), "stderr: {}", String::from_utf8_lossy(&out.stderr));
}

#[test]
fn wrong_group_is_rejected() {
    // SG02 su un gruppo diverso da Ed25519 non e' decifrabile dai token.
    let f = fixture("group", ThresholdScheme::Sg02, Group::Bls12381, 2, 2);
    expect_failure(
        &run(&[("TCN_SG02_PUBKEY", &pk_env(&f)), ("TCN_SG02_LABEL", b"L")], b"x"),
        3,
        "attesa Sg02-Ed25519",
    );
}
