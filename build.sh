#!/bin/bash
# Build every plugin, pack it, write latest/manifest, and clear-sign that manifest with GPG.
set -euo pipefail

root="$(cd "$(dirname "$0")" && pwd)"
vulpes_root="${VULPES_ROOT:-"$root/../vulpes"}"
vulpes_root="${vulpes_root%/}/"
work="$root/out/release"
latest="$root/latest"
hmac_key="121676580bd12b82082d39c91555bbdc2f6d1c0e294461b133f7fbb61b33bdfa"
gpg_key="F9E95ADA0998DB19CB459E666F767BD0B69D5F1C"

if [[ ! -f "${vulpes_root}src/Vulpes.Host/Vulpes.Host.csproj" ]]; then
  echo "Host repo not found at ${vulpes_root}. Set VULPES_ROOT." >&2
  exit 1
fi
if ! command -v gpg >/dev/null || ! command -v python3 >/dev/null; then
  echo "gpg and python3 are required." >&2
  exit 1
fi

plugins=()
while IFS= read -r project; do
  plugins+=("$project")
done < <(find "$root/src" -mindepth 2 -maxdepth 2 -name '*.csproj' -print | sort)
if [[ ${#plugins[@]} -eq 0 ]]; then
  echo "No plugin projects under src/." >&2
  exit 1
fi

rm -rf "$work"
mkdir -p "$work/packages" "$latest"

echo "Publishing host (assemblies the packages must not ship again)..."
dotnet publish "${vulpes_root}src/Vulpes.Host/Vulpes.Host.csproj" -c Release -o "$work/host"

packer="${vulpes_root}tools/Vulpes.PluginPacker/Vulpes.PluginPacker.csproj"
dotnet build "$packer" -c Release --nologo -v q

built_names=()
packed=0
for project in "${plugins[@]}"; do
  dir="$(dirname "$project")"
  name="$(basename "$dir")"
  if [[ ! -f "$dir/plugin.json" ]]; then
    echo "Skipping $name (no plugin.json)."
    continue
  fi
  echo "Publishing $name..."
  dotnet publish "$project" -c Release -o "$work/publish/$name" "/p:VulpesRoot=$vulpes_root"
  archive="$(python3 - "$dir" <<'PY'
import json, pathlib, sys
folder = pathlib.Path(sys.argv[1])
manifest = folder / "plugin.json"
entry = json.loads(manifest.read_text())["entryAssembly"]
print(pathlib.Path(entry).with_suffix(".7z").name)
PY
)"
  built_names+=("$archive")
  prospective="$(mktemp)"
  existing="$(mktemp)"
  dotnet run --project "$packer" -c Release --no-build -- hash \
    --plugin-dir "$work/publish/$name" \
    --host-dir "$work/host" \
    --rid-prefix linux > "$prospective"
  unchanged=0
  if [[ -f "$latest/$archive" ]] \
    && dotnet run --project "$packer" -c Release --no-build -- hash --archive "$latest/$archive" > "$existing" \
    && cmp -s "$prospective" "$existing"; then
    unchanged=1
  fi
  rm -f "$prospective" "$existing"
  if [[ "$unchanged" -eq 1 ]]; then
    echo "Unchanged $archive"
    continue
  fi
  echo "Packing $archive..."
  dotnet run --project "$packer" -c Release --no-build -- \
    --plugin-dir "$work/publish/$name" \
    --host-dir "$work/host" \
    --rid-prefix linux \
    --output "$work/packages/$archive"
  packed=1
done

shopt -s nullglob
for archive in "$work/packages"/*.7z; do
  mv -f "$archive" "$latest/"
done

for existing in "$latest"/*.7z; do
  base="$(basename "$existing")"
  found=0
  for name in "${built_names[@]}"; do
    if [[ "$name" == "$base" ]]; then
      found=1
      break
    fi
  done
  if [[ "$found" -eq 0 ]]; then
    echo "Removing $base (no longer built)."
    rm -f "$existing"
    packed=1
  fi
done

if [[ "$packed" -eq 0 ]]; then
  echo "No plugin package changed. Left latest/manifest as it is."
  exit 0
fi

body="$(mktemp)"
{
  echo "hmac_key:${hmac_key}"
  python3 - "$hmac_key" "$latest" "$work/publish" <<'PY'
import hashlib, hmac, json, pathlib, sys
key = bytes.fromhex(sys.argv[1])
folder = pathlib.Path(sys.argv[2])
publish = pathlib.Path(sys.argv[3])
versions = {}
for manifest_path in publish.glob("*/plugin.json"):
    manifest = json.loads(manifest_path.read_text())
    versions[pathlib.Path(manifest["entryAssembly"]).with_suffix(".7z").name] = manifest["version"]
for package in sorted(folder.glob("*.7z")):
    version = versions.get(package.name)
    if not version:
        raise SystemExit(f"No version for {package.name}. plugin.json was not found in the publish output.")
    digest = hmac.new(key, package.read_bytes(), hashlib.sha512).hexdigest()
    print(f"{package.name}:{digest}:{version}")
PY
} > "$body"

export GPG_TTY="$(tty)"
echo "GPG will ask for the passphrase for ${gpg_key}."
gpg --local-user "$gpg_key" --clearsign --digest-algo SHA512 --output "$latest/manifest" --yes "$body"
rm -f "$body"

echo "Clear-signed manifest and packages are in $latest"
