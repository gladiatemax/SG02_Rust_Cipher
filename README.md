# sg02-encrypt

Cifratura a soglia **SG02** (TDH2, Shoup–Gennaro 2002) sul gruppo **Ed25519**, come binario compilato. La crittografia è interamente quella di [thetacrypt](https://github.com/cryptobern/thetacrypt), usato come libreria: questo programma legge la configurazione, chiama `ThresholdCipher::encrypt` e verifica il risultato.

Produce crittogrammi identici nel formato a quelli di `thetacli enc`, quindi decifrabili dalla catena esistente: decifrature parziali sulle Nitrokey 3 (`theta-app`) e aggregazione sul nodo centrale (TCN). Usa solo la chiave pubblica e non tocca alcun segreto.

## Uso

```sh
export TCN_SG02_PUBKEY=/var/db/tcn/sg02/pub/Sg02-Ed25519_<key_id>.pub
export TCN_SG02_LABEL=blocco-0001

sg02-encrypt < blocco.tar > blocco.tar.sg02
```

| Variabile | Obbligatoria | Significato |
|---|---|---|
| `TCN_SG02_PUBKEY` | sì | Percorso del file `.pub` prodotto da `thetacli keygen` (sottodirectory `pub/`). |
| `TCN_SG02_LABEL` | sì, non vuota | Label legata al crittogramma. Si usano i **byte esatti** della variabile, senza conversioni di codifica. La label entra nella prova di validità del crittogramma: chi decifra la ritrova nel crittogramma e non può alterarla senza invalidarlo. Se cambia fra un blocco e l'altro, va reimpostata a ogni invocazione. |

Il plaintext si legge da **stdin**, il crittogramma (DER) si scrive su **stdout**. Su **stderr** va una riga di riepilogo in caso di successo, o il messaggio d'errore.

Il programma rifiuta stdin e stdout collegati a un terminale, un plaintext vuoto e chiavi di schema o gruppo diversi da SG02-Ed25519. Su un altro gruppo `theta-app` non saprebbe decifrare.

### Codici d'uscita

| Codice | Significato |
|---|---|
| 0 | Crittogramma scritto su stdout. |
| 1 | Errore interno: cifratura o autoverifica fallita. |
| 2 | Configurazione mancante o non valida (variabili, stdin/stdout, plaintext vuoto). |
| 3 | Chiave pubblica illeggibile, malformata, o di schema/gruppo errato. |
| 4 | Errore di I/O su stdin o stdout. |

**Lo stdout è un crittogramma solo se il codice d'uscita è 0.** In caso di errore va scartato. Il parser ASN.1 di thetacrypt, quando una chiave è malformata, scrive diagnostica su stdout e non su stderr: un chiamante che salva stdout su file deve rimuovere il file se il processo non termina con 0. Per esempio:

```sh
sg02-encrypt < in > out.tmp && mv out.tmp out || rm -f out.tmp
```

### Autoverifica

Prima di emettere un solo byte, il programma rilegge il crittogramma serializzato e controlla tre cose: label e key id coincidono con quelli richiesti, e la prova di validità (e, f) supera `verify_ciphertext`, la stessa verifica eseguita da chi decifra. Un crittogramma che esce con codice 0 è quindi ben formato rispetto alla chiave pubblica.

### Limiti

- **Tutto in memoria.** thetacrypt cifra il plaintext con un'unica operazione ChaCha20-Poly1305, quindi l'intero blocco e il crittogramma risiedono in RAM, circa due volte la dimensione del blocco. Il formato non prevede cifratura a stream; cambiarlo renderebbe i crittogrammi incompatibili con la decifratura esistente.
- La lettura di stdin non ha un limite di dimensione: lo stabilisce il chiamante.

## Compilazione

### Requisiti

| Requisito | Perché |
|---|---|
| Rust ≥ 1.88 | `rust-toolchain.toml` fissa la 1.88.0, la toolchain con cui è stato compilato `thetacli` nel sistema di riferimento; con rustup viene selezionata automaticamente. Nessuna dipendenza del `Cargo.lock` richiede una versione più recente. La build è stata provata anche con Rust 1.97. |
| `protoc` (Protocol Buffers) nel `PATH`, o la variabile `PROTOC` | Lo script di build di `theta_proto`, dipendenza di `theta_schemes`, genera codice Rust dai file `.proto` a ogni compilazione. Su FreeBSD: `pkg install protobuf`. |
| Compilatore C, `m4`, GNU make | `rug` → `gmp-mpfr-sys` compila GMP e MPFR dai sorgenti. Su FreeBSD: `pkg install gmake m4`. |

In alternativa a compilare GMP e MPFR si possono usare quelle di sistema, cosa in genere necessaria in **cross-compilazione**, dove la build dai sorgenti di `gmp-mpfr-sys` spesso non riesce:

```sh
pkg install gmp mpfr          # sul sistema di destinazione / nel sysroot
cargo build --release --locked --features system-gmp
```

La feature `system-gmp` attiva `use-system-libs` di `gmp-mpfr-sys`. Non è stata provata in questo ambiente.

### Build

```sh
git clone <url di questo repository>
cd sg02-encrypt
cargo build --release --locked
# binario: target/release/sg02-encrypt
```

`--locked` impone le versioni esatte del `Cargo.lock`, che fa parte del repository. Per una build senza accesso a crates.io:

```sh
cargo vendor --locked vendor    # su una macchina con rete
```

`cargo vendor` stampa una sezione `[source]` da aggiungere in fondo a `.cargo/config.toml`. Da quel momento la build usa solo la directory `vendor/`.

### Avvisi del compilatore

La build non produce avvisi. Quelli di thetacrypt (import e variabili inutilizzati, API deprecate, codice morto) sono disattivati da una tabella `[lints]` aggiunta ai `Cargo.toml` dei crate copiati in `thetacrypt/`. La tabella non tocca il codice sorgente e non si applica a `sg02-encrypt`, per il quale gli avvisi restano attivi. L'elenco dei file modificati è in `thetacrypt/VENDORED.md`.

La stessa tabella disattiva due lint che le toolchain Rust successive alla 1.88 trasformano in errori:

- `dangerous_implicit_autorefs`, in `mcore`, nei moduli RSA non usati da SG02;
- `legacy_derive_helpers`, in `theta_schemes`.

Con la 1.88 fissata non servono, ma proteggono chi compila con il Rust di sistema (es. `pkg install rust` su FreeBSD), che ignora `rust-toolchain.toml`. Sono lint, non errori di tipo: il codice compilato è identico.

`legacy_derive_helpers` segnala un costrutto che una versione futura di Rust rifiuterà del tutto. `.cargo/config.toml` disattiva la nota di future incompatibilità stampata a ogni build. Il limite è noto: con una toolchain che rifiuta quel costrutto, `theta_schemes` va corretto a monte, spostando `#[rasn(enumerated)]` dopo `#[derive(AsnType)]` in `groups/group.rs`.

## Sorgente di thetacrypt

La directory `thetacrypt/` contiene una **copia parziale della versione di thetacrypt usata dal resto del sistema**, con le modifiche locali fatte per la tesi. Il repository originale non va usato. La copia comprende solo:

- `LICENSE.txt` (Apache 2.0);
- `src/core/schemes`, cioè `theta_schemes`, `theta_derive` e `mcore`;
- `src/proto`, cioè `theta_proto`.

Rete, orchestrazione e servizio gRPC restano fuori, anche se `theta_proto` porta comunque con sé `tonic` e `prost`. Lo script di build di `theta_proto` scrive i file generati in `thetacrypt/src/proto/src/`, esclusi da git.

Le modifiche locali riguardano la serializzazione dei punti nell'hash della prova delle decifrature parziali (`h2`), allineata al firmware della Nitrokey 3, e non toccano la cifratura: `encrypt` usa soltanto `to_bytes`, la codifica non compressa, invariata. La copia serve comunque a far compilare lo stesso codice a chi cifra e a chi decifra.

### Aggiornare la copia

```sh
scripts/vendor-thetacrypt.sh /percorso/a/thetacrypt
cargo test --release --locked
git add thetacrypt && git commit
```

Lo script sostituisce l'intera directory `thetacrypt/`. Se la sorgente è un clone git, registra anche:

- in `thetacrypt/VENDORED.md`, il commit di partenza, il remote e l'elenco dei file modificati;
- in `thetacrypt/MODIFICHE.patch`, il diff delle modifiche locali.

Questo rende verificabile l'origine del codice e assolve l'obbligo di segnalare i file modificati previsto dalla licenza Apache 2.0 (sez. 4b).

## Test

```sh
cargo test --release --locked
```

I test d'integrazione (`tests/roundtrip.rs`) generano un gruppo SG02-Ed25519 2-su-3, lanciano il binario come processo esterno e decifrano con thetacrypt (`partial_decrypt`, `verify_share`, `assemble`) con ogni coppia di share. Verificano anche:

- la conservazione esatta della label, compresi byte non UTF-8;
- la randomizzazione dei crittogrammi;
- il rifiuto di un crittogramma con label alterata;
- i codici d'uscita per configurazione mancante, chiave assente o malformata, gruppo errato.

La compatibilità con le decifrature parziali calcolate dalla Nitrokey 3 non è coperta da questi test: va verificata con la catena del TCN.

## Che cosa fa la cifratura

Per riferimento, quello che esegue `Sg02ThresholdCipher::encrypt` di thetacrypt. Le formule sono in notazione additiva, con G il generatore, Ḡ il secondo generatore fissato nella chiave pubblica e Y la chiave pubblica di gruppo.

1. r ← Zq casuale; U = r·G; rY = r·Y.
2. k ← 32 byte casuali (via HKDF-SHA256); il messaggio viene cifrato con ChaCha20-Poly1305 sotto la chiave k, con nonce pari ai primi 12 byte della codifica non compressa di rY.
3. c_k = SHA-256(rY) ⊕ k.
4. s ← Zq casuale; W = s·G, W̄ = s·Ḡ, Ū = r·Ḡ.
5. e = H1(c_k, label, U, W, Ū, W̄), f = s + r·e mod q.

Crittogramma: (label, ctxt, U, Ū, e, f, c_k, key_id). La casualità viene da `OsRng`, cioè da `getrandom(2)` su FreeBSD.
