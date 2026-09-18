#!/bin/sh
# Build-time gate for the FIPS image. Allowlist logic: every ELF in the final
# layers must be accounted for, either present in fips_elf_inventory.txt
# (reviewed as crypto-free or linked against the validated system
# libcrypto.so.3) or waived below when it bundles its own crypto
# implementation. A binary that is neither fails the build, so a new native
# dependency cannot ship without review, whatever crypto it embeds.
#
# SCAN_EMIT_INVENTORY=1 prints normalized ELF paths instead of gating.
# Regenerate the inventory after a reviewed dependency change with:
#   docker run --rm -v "$PWD/docker:/scan" --entrypoint sh <image> -c \
#     'SCAN_EMIT_INVENTORY=1 /scan/scan_bundled_crypto.sh /app/.venv /opt/prisma /usr/local/bin' \
#     > docker/fips_elf_inventory.txt
set -eu

script_dir="$(cd "$(dirname "$0")" && pwd)"
inventory="${SCAN_INVENTORY:-$script_dir/fips_elf_inventory.txt}"
report="${SCAN_REPORT:-/fips-scan-report.txt}"
failures="$(mktemp)"
counts="$(mktemp)"

normalize() {
  printf '%s\n' "$1" | sed \
    -e 's/aarch64/ARCH/g' \
    -e 's/x86_64/ARCH/g' \
    -e 's/-[0-9a-f]\{8,\}\(\.so\)/\1/'
}

is_elf() {
  [ "$(head -c 4 "$1" 2>/dev/null)" = "$(printf '\177ELF')" ]
}

crypto_markers() {
  m=""
  if grep -aq 'BoringSSL' "$1"; then m="BoringSSL"; fi
  if grep -aq 'AWS-LC' "$1"; then m="${m:+$m,}AWS-LC"; fi
  if grep -Eaq 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+' "$1"; then
    if ! objdump -p "$1" 2>/dev/null | grep -q 'NEEDED.*libcrypto\.so\.3'; then
      m="${m:+$m,}bundled-OpenSSL"
    fi
  fi
  if grep -aq 'sodium_init' "$1"; then m="${m:+$m,}libsodium"; fi
  if grep -aq 'ring_core_' "$1"; then m="${m:+$m,}ring"; fi
  if grep -aq 'rustls' "$1"; then m="${m:+$m,}rustls"; fi
  if grep -Eaqi 'mbed.?tls' "$1"; then m="${m:+$m,}mbedTLS"; fi
  if grep -aq 'wolfSSL' "$1"; then m="${m:+$m,}wolfSSL"; fi
  if grep -aq 'libgcrypt' "$1"; then m="${m:+$m,}libgcrypt"; fi
  printf '%s' "$m"
}

waived_reason() {
  case "$1" in
    */cryptography/hazmat/bindings/_rust.abi3.so)
      echo "wheel bundles OpenSSL; workstream C source-builds against system OpenSSL" ;;
    */grpc/_cython/cygrpc*.so)
      echo "bundles BoringSSL; workstream C source-builds with system OpenSSL or drops grpcio" ;;
    */hf_xet/hf_xet.abi3.so)
      echo "bundles BoringSSL; found by this scan, not in the roadmap inventory; workstream C drops or rebuilds it" ;;
    */_awscrt.abi3.so)
      echo "bundles aws-lc (BoringSSL fork); found by this scan; workstream C drops the bedrock-realtime extra or source-builds awscrt" ;;
    */pyroscope/_native__lib*.so)
      echo "bundles BoringSSL; found by this scan; workstream C drops pyroscope from the FIPS build" ;;
    */psycopg_binary.libs/libcrypto-*)
      echo "psycopg_binary wheel bundles OpenSSL; found by this scan; workstream C switches to source-built psycopg" ;;
    */nacl/_sodium*.so|*/libsodium*)
      echo "bundles libsodium; workstream C drops pynacl from the FIPS build" ;;
    */litellm/rust_bridge/*|*/granian*)
      echo "bundles a Rust TLS stack; workstream C excludes it from the FIPS build" ;;
    */xmlsec*|*xmlsec.libs*)
      echo "bundles libxmlsec1+OpenSSL; workstream C drops the saml extra" ;;
    */_polars_runtime_32/_polars_runtime.abi3.so)
      echo "bundles ring/rustls for cloud-storage readers; found by this scan; workstream C reviews whether polars is needed in the FIPS build" ;;
    */ddtrace/internal/native/_native*.so)
      echo "bundles ring/rustls; found by this scan; workstream C drops or reviews ddtrace in the FIPS build" ;;
    /opt/prisma/*query-engine*|/opt/prisma/*schema-engine*)
      echo "prisma engines carry rustls alongside the dynamic system-OpenSSL link; found by this scan; workstream C confirms which TLS stack serves DB connections" ;;
    *)
      return 1 ;;
  esac
}

if [ "${SCAN_EMIT_INVENTORY:-}" = "1" ]; then
  find "$@" -type f 2>/dev/null | while read -r f; do
    if is_elf "$f"; then
      normalize "$f"
    fi
  done | sort -u
  exit 0
fi

if [ ! -f "$inventory" ]; then
  echo "FAIL: inventory file not found at $inventory" >&2
  exit 1
fi

: > "$report"
find "$@" -type f 2>/dev/null | sort | while read -r f; do
  if ! is_elf "$f"; then
    continue
  fi
  echo scanned >> "$counts"
  norm="$(normalize "$f")"
  markers="$(crypto_markers "$f")"
  if [ -n "$markers" ]; then
    if reason="$(waived_reason "$f")"; then
      printf 'WAIVED    %s [%s] %s\n' "$f" "$markers" "$reason" | tee -a "$report"
    else
      printf 'VIOLATION %s [%s] bundled crypto with no waiver\n' "$f" "$markers" | tee -a "$report"
      echo "$f" >> "$failures"
    fi
  elif ! grep -Fxq "$norm" "$inventory"; then
    printf 'VIOLATION %s [unreviewed] not in fips_elf_inventory.txt; review it, then regenerate the inventory\n' "$f" | tee -a "$report"
    echo "$f" >> "$failures"
  fi
done

scanned="$(grep -c scanned "$counts" || true)"
if [ -s "$failures" ]; then
  printf 'FAIL: %s of %s ELF binaries unaccounted for (see above)\n' "$(wc -l < "$failures" | tr -d ' ')" "$scanned" | tee -a "$report"
  exit 1
fi
printf 'PASS: all %s ELF binaries accounted for (inventoried, system-linked, or waived)\n' "$scanned" | tee -a "$report"
