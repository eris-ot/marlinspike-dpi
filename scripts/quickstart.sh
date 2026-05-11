#!/usr/bin/env bash
#
# marlinspike-dpi quickstart
#
# Fetches a public sample PCAP and runs marlinspike-dpi against it in
# all three output formats. Designed for a 2-minute "try it before I
# commit to installing it" evaluation flow.
#
# Usage:
#     ./scripts/quickstart.sh                # uses ./target/release/marlinspike-dpi (cargo build --release first)
#     ./scripts/quickstart.sh --docker        # uses `docker run marlinspike-dpi:latest`
#     ./scripts/quickstart.sh /path/to/dpi    # uses an explicit binary path
#
# Sample PCAP source: the public ICS-Pcaps archive at
# https://github.com/automayt/ICS-pcap (CC-BY). We fetch a small Modbus
# capture as it exercises the deepest end of our parser surface and is
# representative of OT traffic.

set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RESET='\033[0m'

mode="local"
binary="./target/release/marlinspike-dpi"

case "${1:-}" in
    --docker)
        mode="docker"
        ;;
    "")
        ;;
    *)
        if [[ -x "$1" ]]; then
            binary="$1"
        else
            echo "usage: $0 [--docker | /path/to/marlinspike-dpi]" >&2
            exit 2
        fi
        ;;
esac

workdir=$(mktemp -d)
trap 'rm -rf "$workdir"' EXIT

cap_url="https://raw.githubusercontent.com/automayt/ICS-pcap/master/MODBUS%20TCP/Modbus_Polling_Master_RealValues.pcap"
cap_file="$workdir/sample.pcap"

echo -e "${CYAN}▶ fetching sample Modbus/TCP capture…${RESET}"
if ! curl -fsSL --max-time 30 -o "$cap_file" "$cap_url"; then
    cat >&2 <<EOF

Failed to fetch the sample PCAP. Common causes:
  - No internet access (this script requires curl to the public archive)
  - The upstream archive moved or is rate-limited

Workaround: bring your own PCAP and pass its path directly:
    $binary --input /your/capture.pcap --pretty | head -50

Or pick one from these public archives:
  https://wiki.wireshark.org/SampleCaptures
  https://github.com/automayt/ICS-pcap
  https://github.com/ITI/ICS-Security-Tools/tree/master/pcaps

EOF
    exit 1
fi
echo "  saved to $cap_file ($(wc -c < "$cap_file" | tr -d ' ') bytes)"

run() {
    if [[ "$mode" = "docker" ]]; then
        docker run --rm -v "$cap_file:/in.pcap:ro" marlinspike-dpi:latest "$@" --input /in.pcap
    else
        "$binary" "$@" --input "$cap_file"
    fi
}

if [[ "$mode" = "local" && ! -x "$binary" ]]; then
    echo "binary not found at $binary — run \`cargo build --release\` first, or use --docker" >&2
    exit 1
fi

echo
echo -e "${CYAN}▶ Bronze v2 JSON (default — first 30 lines):${RESET}"
run --format bronze --pretty | head -30

echo
echo -e "${CYAN}▶ OCSF v1.4.0 NDJSON (first 5 records):${RESET}"
run --format ocsf 2>/dev/null | head -5

echo
echo -e "${CYAN}▶ InfluxDB Line Protocol — ProcessReadings only (first 10 lines):${RESET}"
run --format influx 2>/dev/null | head -10 || echo "  (no ProcessReadings in this Modbus capture — try Sparkplug B or OPC UA for VQT)"

echo
echo -e "${GREEN}▶ done — see README.md for library/FFI usage and docs/ for the full schema reference${RESET}"
