//! sg02-encrypt — cifratura a soglia SG02 (TDH2, Shoup-Gennaro 2002) su
//! Ed25519, tramite la libreria thetacrypt.
//!
//! Sostituisce `hosttools.sg02_encrypt` del TCN, che invocava
//! `thetacli enc --pubkey=... --label=...` passando i dati attraverso
//! file temporanei. Qui nessun file intermedio: plaintext da stdin,
//! crittogramma su stdout. La configurazione arriva dall'ambiente.
//!
//!   TCN_SG02_PUBKEY   percorso del file .pub prodotto da `thetacli keygen`
//!   TCN_SG02_LABEL    label legata al crittogramma (byte esatti della variabile)
//!
//! Usa solo materiale pubblico: nessun segreto passa da questo processo,
//! a parte il plaintext stesso.
//!
//! Codici d'uscita:
//!   0  crittogramma scritto su stdout
//!   2  configurazione mancante o non valida
//!   3  chiave pubblica illeggibile, malformata o di schema/gruppo errato
//!   4  errore di I/O su stdin o stdout
//!   1  errore interno (cifratura fallita o autoverifica non superata)
//!
//! Se il codice d'uscita non e' 0, il contenuto di stdout NON e' un
//! crittogramma e va scartato (il parser ASN.1 di thetacrypt, in caso di
//! errore, stampa diagnostica su stdout).

use std::env;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::os::unix::ffi::OsStringExt;
use std::panic::{self, AssertUnwindSafe};
use std::path::PathBuf;
use std::process::ExitCode;

use theta_schemes::interface::{Ciphertext, Serializable, ThresholdCipher, ThresholdCipherParams};
use theta_schemes::keys::keys::PublicKey;

const ENV_PUBKEY: &str = "TCN_SG02_PUBKEY";
const ENV_LABEL: &str = "TCN_SG02_LABEL";

/// Schema e gruppo ammessi. Il firmware theta-app implementa solo
/// SG02 su Ed25519: un crittogramma su un altro gruppo non sarebbe
/// decifrabile dai token.
const EXPECTED_SCHEME: &str = "Sg02";
const EXPECTED_GROUP: &str = "Ed25519";

enum Error {
    Config(String),
    Key(String),
    Io(String),
    Internal(String),
}

impl Error {
    fn exit_code(&self) -> u8 {
        match self {
            Error::Config(_) => 2,
            Error::Key(_) => 3,
            Error::Io(_) => 4,
            Error::Internal(_) => 1,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) => write!(f, "configurazione: {m}"),
            Error::Key(m) => write!(f, "chiave pubblica: {m}"),
            Error::Io(m) => write!(f, "I/O: {m}"),
            Error::Internal(m) => write!(f, "interno: {m}"),
        }
    }
}

/// Esegue `f` trasformando un eventuale panic di thetacrypt in errore.
/// Il messaggio del panic e' gia' stato scritto su stderr dall'hook
/// predefinito; qui serve solo a non uscire con un codice generico.
fn guarded<T>(what: &str, f: impl FnOnce() -> T) -> Result<T, String> {
    panic::catch_unwind(AssertUnwindSafe(f)).map_err(|_| format!("panic in thetacrypt durante {what}"))
}

/// Legge una variabile d'ambiente obbligatoria e non vuota, come byte grezzi.
fn required_env(name: &str) -> Result<OsString, Error> {
    match env::var_os(name) {
        None => Err(Error::Config(format!("{name} non impostata"))),
        Some(v) if v.is_empty() => Err(Error::Config(format!("{name} e' vuota"))),
        Some(v) => Ok(v),
    }
}

fn load_public_key() -> Result<(PathBuf, PublicKey), Error> {
    let path = PathBuf::from(required_env(ENV_PUBKEY)?);

    let bytes = fs::read(&path)
        .map_err(|e| Error::Key(format!("lettura di {} fallita: {e}", path.display())))?;
    if bytes.is_empty() {
        return Err(Error::Key(format!("{} e' vuoto", path.display())));
    }

    let pk = guarded("la deserializzazione", || PublicKey::from_bytes(&bytes))
        .map_err(Error::Key)?
        .map_err(|e| Error::Key(format!("{} non e' una chiave pubblica thetacrypt valida: {e}", path.display())))?;

    let scheme = pk.get_scheme();
    let group = pk.get_group();
    if scheme.as_str_name() != EXPECTED_SCHEME || group.as_str_name() != EXPECTED_GROUP {
        return Err(Error::Key(format!(
            "{} e' una chiave {}-{}, attesa {EXPECTED_SCHEME}-{EXPECTED_GROUP}",
            path.display(),
            scheme.as_str_name(),
            group.as_str_name()
        )));
    }

    Ok((path, pk))
}

fn read_plaintext() -> Result<Vec<u8>, Error> {
    let mut stdin = io::stdin().lock();
    if stdin.is_terminal() {
        return Err(Error::Config("stdin e' un terminale: passare il plaintext in pipe o con redirezione".into()));
    }
    let mut buf = Vec::new();
    stdin
        .read_to_end(&mut buf)
        .map_err(|e| Error::Io(format!("lettura di stdin fallita: {e}")))?;
    if buf.is_empty() {
        return Err(Error::Config("plaintext vuoto su stdin".into()));
    }
    Ok(buf)
}

fn run() -> Result<(), Error> {
    // Ordine dei controlli: prima tutto cio' che non costa nulla, cosi'
    // un errore di configurazione non consuma lo stdin del chiamante.
    let label = required_env(ENV_LABEL)?.into_vec();
    let (pk_path, pk) = load_public_key()?;

    let stdout = io::stdout();
    if stdout.is_terminal() {
        return Err(Error::Config("stdout e' un terminale: il crittogramma e' binario, redirigerlo su file o pipe".into()));
    }

    let plaintext = read_plaintext()?;

    // Cifratura. ThresholdCipherParams::new() usa OsRng (getrandom(2) su
    // FreeBSD) per r, s e la chiave simmetrica.
    let ct_bytes = guarded("la cifratura", || -> Result<Vec<u8>, String> {
        let mut params = ThresholdCipherParams::new();
        let ct = ThresholdCipher::encrypt(&plaintext, &label, &pk, &mut params)
            .map_err(|e| format!("cifratura fallita: {e}"))?;
        ct.to_bytes().map_err(|e| format!("serializzazione fallita: {e}"))
    })
    .map_err(Error::Internal)?
    .map_err(Error::Internal)?;

    // Autoverifica prima di emettere qualsiasi byte: il crittogramma
    // deve rileggersi e la prova di validita' (e, f) deve passare la
    // stessa verifica che fanno i nodi. Costa due esponenziazioni
    // multiple, trascurabili rispetto al resto della pipeline.
    guarded("l'autoverifica", || -> Result<(), String> {
        let parsed = Ciphertext::from_bytes(&ct_bytes).map_err(|e| format!("crittogramma non rileggibile: {e}"))?;
        if parsed.get_label() != label.as_slice() {
            return Err("label del crittogramma diversa da quella richiesta".into());
        }
        if parsed.get_key_id() != pk.get_key_id() {
            return Err("key id del crittogramma diverso da quello della chiave".into());
        }
        match ThresholdCipher::verify_ciphertext(&parsed, &pk) {
            Ok(true) => Ok(()),
            Ok(false) => Err("prova di validita' del crittogramma non verificata".into()),
            Err(e) => Err(format!("verifica fallita: {e}")),
        }
    })
    .map_err(Error::Internal)?
    .map_err(Error::Internal)?;

    let mut out = stdout.lock();
    out.write_all(&ct_bytes)
        .and_then(|_| out.flush())
        .map_err(|e| Error::Io(format!("scrittura su stdout fallita: {e}")))?;

    eprintln!(
        "sg02-encrypt OK: key_id={} pubkey={} label={} B plaintext={} B ciphertext={} B",
        pk.get_key_id(),
        pk_path.display(),
        label.len(),
        plaintext.len(),
        ct_bytes.len()
    );
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("sg02-encrypt: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}
