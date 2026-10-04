#!/usr/bin/env bash
# Generate every test image from one raw image into fixtures/out/.
#
# Needs macOS (hdiutil), libewf (ewfacquire, ewfverify), qemu-img, python3,
# and a release build of aff4tools at ../aff4tools. Everything goes to
# fixtures/out/. Rerun after changing this script or
# upgrading any of the tools.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$HERE/out"
AFF4TOOLS="$ROOT/../aff4tools/target/release/aff4tools"
RAW_MIB=16
UNREADABLE_OFFSET=$((1024 * 1024))
UNREADABLE_LENGTH=$((64 * 1024))
CHUNK_BYTES=32768   # ewfacquire -b 64: 64 sectors of 512 bytes

need() { command -v "$1" >/dev/null || { echo "missing tool: $1" >&2; exit 1; }; }
for t in hdiutil ewfacquire ewfverify qemu-img python3 shasum; do need "$t"; done
[ -x "$AFF4TOOLS" ] || { echo "build aff4tools first: cargo build --release --manifest-path ../aff4tools/Cargo.toml" >&2; exit 1; }

WORK="$(mktemp -d)"
cleanup() {
  hdiutil detach "$WORK/mnt" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

rm -rf "$OUT"
mkdir -p "$OUT"/{e01,e01-multi,e01-corrupt,vmdk,vmdk-missing-parent,aff4,aff4-unreadable}

echo "== raw image: GPT with one APFS volume, holding a few files"
hdiutil create -size "${RAW_MIB}m" -fs APFS -layout GPTSPUD -volname FIXTURE \
  -type UDIF "$WORK/raw.dmg" >/dev/null
mkdir "$WORK/mnt"
hdiutil attach -nobrowse -mountpoint "$WORK/mnt" "$WORK/raw.dmg" >/dev/null
printf 'hello from the blockreader-adapters fixture\n' > "$WORK/mnt/hello.txt"
mkdir "$WORK/mnt/dir"
python3 -c 'import sys; sys.stdout.buffer.write(bytes(i % 251 for i in range(300000)))' \
  > "$WORK/mnt/dir/pattern.bin"
hdiutil detach "$WORK/mnt" >/dev/null
hdiutil convert "$WORK/raw.dmg" -format UDTO -o "$WORK/raw" >/dev/null
mv "$WORK/raw.cdr" "$OUT/raw.img"
RAW_SIZE=$(stat -f %z "$OUT/raw.img")
RAW_SHA256=$(shasum -a 256 "$OUT/raw.img" | cut -d' ' -f1)

echo "== E01"
# Fixed case and examiner fields, so nothing identifies this machine.
EWF_FIELDS=(-C fixture -D "blockreader-adapters fixture" -E 1 -e fixture -N generated -m fixed -M physical)
if ewfacquire -h 2>&1 | grep -q "deflate:"; then
  FAST="deflate:fast"; NONE="none"
else
  FAST="fast"; NONE="none"
fi
ewfacquire -u -q -f encase6 -b 64 -c "$FAST" "${EWF_FIELDS[@]}" \
  -t "$OUT/e01/disk" "$OUT/raw.img" >/dev/null
ewfacquire -u -q -f encase6 -b 64 -c "$NONE" -S 1048576 "${EWF_FIELDS[@]}" \
  -t "$OUT/e01-multi/disk" "$OUT/raw.img" >/dev/null
[ -f "$OUT/e01-multi/disk.E02" ] || { echo "the multi-segment E01 has one segment" >&2; exit 1; }

echo "== corrupt E01: flip one byte inside a chunk"
CORRUPTED=""
for pct in 50 55 60 65 70 45 40 35 30; do
  cp "$OUT/e01/disk.E01" "$OUT/e01-corrupt/disk.E01"
  python3 - "$OUT/e01-corrupt/disk.E01" "$pct" <<'PY'
import sys
path, pct = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    f.seek(0, 2)
    at = f.tell() * pct // 100
    f.seek(at)
    b = f.read(1)
    f.seek(at)
    f.write(bytes([b[0] ^ 0xFF]))
PY
  # A chunk-data corruption opens, then fails verification with a sector error.
  if ! ewfverify -q "$OUT/e01-corrupt/disk.E01" >"$WORK/verify.txt" 2>&1 \
      && grep -qi "sector" "$WORK/verify.txt"; then
    CORRUPTED="$pct"
    break
  fi
done
[ -n "$CORRUPTED" ] || { echo "could not corrupt a chunk's data" >&2; exit 1; }

echo "== VMDK"
qemu-img convert -f raw -O vmdk -o subformat=monolithicSparse "$OUT/raw.img" "$OUT/vmdk/disk-sparse.vmdk"
qemu-img convert -f raw -O vmdk -o subformat=monolithicFlat "$OUT/raw.img" "$OUT/vmdk/disk-flat.vmdk"
qemu-img convert -f raw -O vmdk -o subformat=streamOptimized "$OUT/raw.img" "$OUT/vmdk/disk-stream.vmdk"
# A delta disk whose parent does not exist beside it.
cp "$OUT/vmdk/disk-sparse.vmdk" "$WORK/parent.vmdk"
( cd "$WORK" && qemu-img create -f vmdk -F vmdk -b parent.vmdk delta.vmdk >/dev/null )
mv "$WORK/delta.vmdk" "$OUT/vmdk-missing-parent/delta.vmdk"

echo "== AFF4"
"$AFF4TOOLS" acquire --image "$OUT/raw.img" --output "$OUT/aff4/disk.aff4" >/dev/null
( cd "$ROOT" && cargo run -q -p contract-tests --example make_unreadable_aff4 -- \
    "$OUT/raw.img" "$OUT/aff4-unreadable/disk.aff4" "$UNREADABLE_OFFSET" "$UNREADABLE_LENGTH" )

echo "== manifest"
cat > "$OUT/manifest.json" <<JSON
{
  "raw": { "path": "raw.img", "size": $RAW_SIZE, "sha256": "$RAW_SHA256" },
  "fixtures": [
    { "name": "e01", "path": "e01/disk.E01", "format": "e01",
      "sector_bytes": 512, "sector_basis": "recorded", "unknown": { "kind": "none" } },
    { "name": "e01-multi", "path": "e01-multi/disk.E01", "format": "e01",
      "sector_bytes": 512, "sector_basis": "recorded", "unknown": { "kind": "none" } },
    { "name": "e01-corrupt", "path": "e01-corrupt/disk.E01", "format": "e01",
      "sector_bytes": 512, "sector_basis": "recorded",
      "unknown": { "kind": "one-chunk", "chunk_bytes": $CHUNK_BYTES, "cause": "failed-integrity" } },
    { "name": "vmdk-sparse", "path": "vmdk/disk-sparse.vmdk", "format": "vmdk",
      "sector_bytes": 512, "sector_basis": "assumed", "unknown": { "kind": "none" } },
    { "name": "vmdk-flat", "path": "vmdk/disk-flat.vmdk", "format": "vmdk",
      "sector_bytes": 512, "sector_basis": "assumed", "unknown": { "kind": "none" } },
    { "name": "vmdk-stream", "path": "vmdk/disk-stream.vmdk", "format": "vmdk",
      "sector_bytes": 512, "sector_basis": "assumed", "unknown": { "kind": "none" } },
    { "name": "aff4", "path": "aff4/disk.aff4", "format": "aff4",
      "sector_bytes": 512, "sector_basis": "assumed", "unknown": { "kind": "none" } },
    { "name": "aff4-unreadable", "path": "aff4-unreadable/disk.aff4", "format": "aff4",
      "sector_bytes": 512, "sector_basis": "assumed",
      "unknown": { "kind": "ranges", "ranges": [
        { "offset": $UNREADABLE_OFFSET, "len": $UNREADABLE_LENGTH, "cause": "unreadable-at-acquisition" } ] } }
  ],
  "missing_parent": "vmdk-missing-parent/delta.vmdk"
}
JSON

echo "done: $OUT (raw $RAW_SIZE bytes, sha256 $RAW_SHA256; E01 corrupted at ${CORRUPTED}%)"
