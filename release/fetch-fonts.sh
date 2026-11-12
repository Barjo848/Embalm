#!/bin/bash
# Optional. Copies the three typefaces the design calls for into release/fonts:
#
#   bash release/fetch-fonts.sh <folder holding the three font files>
#
# The fonts are not in the repository. TeX Gyre Heros (Regular, Bold) is free under
# the GUST Font License: https://www.gust.org.pl/projects/e-foundry/tex-gyre/heros
# Courier Code is a commercial Bitstream face and may only be used under your own
# licence. Without the fonts, Embalm builds and runs with system typefaces.
set -euo pipefail
SRC="${1:-${EMBALM_FONTS_DIR:-}}"
[ -n "$SRC" ] || { echo "usage: bash release/fetch-fonts.sh <folder holding the three font files>"; exit 64; }
DEST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/fonts"
mkdir -p "$DEST"
for f in TeXGyreHeros-Regular.otf TeXGyreHeros-Bold.otf CourierCode-Roman.ttf; do
    [ -f "$SRC/$f" ] || { echo "missing $SRC/$f"; exit 1; }
    cp "$SRC/$f" "$DEST/"
done
echo "fonts ready in $DEST"
