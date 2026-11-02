#!/bin/sh
# vendor-thetacrypt.sh — copia in ./thetacrypt la parte di thetacrypt
# necessaria alla cifratura SG02, a partire da una copia locale (anche con
# modifiche non committate).
#
#   scripts/vendor-thetacrypt.sh /percorso/a/thetacrypt
#
# Si copiano solo:
#   LICENSE.txt
#   src/core/schemes   (theta_schemes, theta_derive, mcore)
#   src/proto          (theta_proto; i .rs generati da protoc vengono esclusi)
#
# Se la sorgente e' un clone git, in thetacrypt/VENDORED.md si registrano
# commit e remote di partenza, e in thetacrypt/MODIFICHE.patch il diff delle
# modifiche locali rispetto a quel commit. Serve a ricostruire l'origine del
# codice e a soddisfare l'obbligo di segnalare i file modificati della
# licenza Apache 2.0 (sez. 4b).
#
# POSIX sh: funziona su Linux e FreeBSD.

set -eu

die() { echo "vendor-thetacrypt: $*" >&2; exit 1; }

[ $# -eq 1 ] || die "uso: $0 <percorso di thetacrypt>"
SRC=$(cd "$1" 2>/dev/null && pwd) || die "$1 non e' una directory"
[ -f "$SRC/src/core/schemes/Cargo.toml" ] || die "$SRC non sembra thetacrypt (manca src/core/schemes/Cargo.toml)"
[ -f "$SRC/src/proto/Cargo.toml" ] || die "$SRC non sembra thetacrypt (manca src/proto/Cargo.toml)"
[ -f "$SRC/LICENSE.txt" ] || die "manca $SRC/LICENSE.txt: la licenza va copiata insieme al codice"

ROOT=$(cd "$(dirname "$0")/.." && pwd)
DEST="$ROOT/thetacrypt"
case "$DEST" in
    "$SRC"|"$SRC"/*) die "la destinazione $DEST e' dentro la sorgente" ;;
esac

rm -rf "$DEST"
mkdir -p "$DEST/src/core"
cp "$SRC/LICENSE.txt" "$DEST/"
cp -R "$SRC/src/core/schemes" "$DEST/src/core/"
cp -R "$SRC/src/proto" "$DEST/src/"

# Artefatti di build e codice generato: non sono sorgenti.
find "$DEST" -type d \( -name target -o -name .git \) -prune -exec rm -rf {} +
for f in protocol_types.rs proxy_api.rs scheme_types.rs; do
    rm -f "$DEST/src/proto/src/$f"
done

PATHS="src/core/schemes src/proto"
{
    echo "# thetacrypt (copia parziale)"
    echo
    echo "Copiato con \`scripts/vendor-thetacrypt.sh\` il $(date -u '+%Y-%m-%d %H:%M UTC')."
    echo "Contiene solo LICENSE.txt, $PATHS. Licenza: Apache 2.0 (LICENSE.txt)."
    echo
    if git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
        echo "- Upstream: $(git -C "$SRC" remote get-url origin 2>/dev/null || echo 'nessun remote origin')"
        echo "- Commit di partenza: $(git -C "$SRC" rev-parse HEAD)"
        echo
        # shellcheck disable=SC2086
        CHANGES=$(cd "$SRC" && git status --porcelain -- $PATHS)
        if [ -n "$CHANGES" ]; then
            echo "## File modificati rispetto al commit di partenza"
            echo
            echo '```'
            echo "$CHANGES"
            echo '```'
            echo
            echo "Il diff dei file tracciati e' in \`MODIFICHE.patch\`. I file marcati \`??\` sono"
            echo "nuovi (non tracciati) e compaiono per intero nella copia."
        else
            echo "Nessuna modifica locale: la copia coincide con il commit di partenza."
        fi
    else
        echo "La sorgente non e' un clone git: commit di partenza e modifiche non"
        echo "sono ricostruibili automaticamente. Annotarli qui a mano."
    fi
} > "$DEST/VENDORED.md"

if git -C "$SRC" rev-parse --git-dir >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    (cd "$SRC" && git diff HEAD -- $PATHS) > "$DEST/MODIFICHE.patch"
    [ -s "$DEST/MODIFICHE.patch" ] || rm -f "$DEST/MODIFICHE.patch"
fi

echo "thetacrypt copiato in $DEST ($(du -sk "$DEST" | cut -f1) KB)."
echo "Controllare $DEST/VENDORED.md, poi: cargo test --release --locked"
