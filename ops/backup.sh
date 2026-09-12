#!/usr/bin/env bash
# backup.sh — ghostpay state backup, cron-ready (runs on the VPS as root):
#
#   41 3 * * * /opt/ghostpay/ops/backup.sh >> /var/log/ghostpay-backup.log 2>&1
#
# tars /opt/ghostpay/{fees.jsonl,broadcasts.jsonl,ghostpay.env} into
# /root/backups/ghostpay-<datestamp>.tar.gz (mode 600, dir 700) and keeps the last 12.
# ghostpay.env holds secrets: never copy these archives anywhere world-readable.
set -euo pipefail

SRC="${SRC_DIR:-/opt/ghostpay}"
DEST="${DEST_DIR:-/root/backups}"
KEEP="${KEEP:-12}"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="$DEST/ghostpay-$STAMP.tar.gz"

FILES=()
for f in fees.jsonl broadcasts.jsonl ghostpay.env; do
  if [ -f "$SRC/$f" ]; then FILES+=("$f"); fi
done
if [ "${#FILES[@]}" -eq 0 ]; then
  echo "backup: nothing to back up in $SRC (no fees.jsonl, broadcasts.jsonl or ghostpay.env)" >&2
  exit 1
fi

mkdir -p "$DEST"
chmod 700 "$DEST"
umask 077
tar -czf "$OUT" -C "$SRC" "${FILES[@]}"
chmod 600 "$OUT"
echo "backup: wrote $OUT (${#FILES[@]} file(s): ${FILES[*]})"

# prune: keep the newest $KEEP archives
ls -1t "$DEST"/ghostpay-*.tar.gz 2>/dev/null | tail -n +$((KEEP + 1)) | while read -r old; do
  rm -f "$old"
  echo "backup: pruned $old"
done
