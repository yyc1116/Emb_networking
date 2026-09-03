#!/bin/sh
# Run netmon and tcpdump together, then preserve report-ready evidence on exit.

set -eu

usage() {
    echo "Usage: $0 -i <interface> --gpio-line <line> [--gpio-chip <path>] [--output-dir <path>]" >&2
    exit 2
}

interface=""
gpio_chip="/dev/gpiochip0"
gpio_line=""
output_dir=""
tcpdump_pid=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        -i)
            [ "$#" -ge 2 ] || usage
            interface="$2"
            shift 2
            ;;
        --gpio-chip)
            [ "$#" -ge 2 ] || usage
            gpio_chip="$2"
            shift 2
            ;;
        --gpio-line)
            [ "$#" -ge 2 ] || usage
            gpio_line="$2"
            shift 2
            ;;
        --output-dir)
            [ "$#" -ge 2 ] || usage
            output_dir="$2"
            shift 2
            ;;
        -h|--help)
            usage
            ;;
        *)
            usage
            ;;
    esac
done

[ -n "$interface" ] || usage
[ -n "$gpio_line" ] || usage
[ -x "./netmon" ] || {
    echo "Error: run this script from the directory containing the GPIO-enabled ./netmon binary." >&2
    exit 1
}
command -v tcpdump >/dev/null 2>&1 || {
    echo "Error: tcpdump is required to create the verification file." >&2
    exit 1
}

if [ -z "$output_dir" ]; then
    output_dir="./netmon_evidence_$(date +%Y%m%d-%H%M%S)-$$"
fi

mkdir -p "$output_dir"
pcap_file="$output_dir/netmon_verify.pcap"
summary_file="$output_dir/tcpdump_summary.txt"
key_file="$output_dir/tcpdump_key_lines.txt"
log_file="$output_dir/netmon_gpio_final.log"

cleanup() {
    if [ -n "$tcpdump_pid" ]; then
        sudo kill "$tcpdump_pid" 2>/dev/null || true
        wait "$tcpdump_pid" 2>/dev/null || true
    fi

    if [ -f "$pcap_file" ]; then
        sudo chmod a+r "$pcap_file" 2>/dev/null || true
        tcpdump -nn -tttt -r "$pcap_file" > "$summary_file" 2>/dev/null || true
        grep -E 'ICMP|Flags \[S\]|\.53:' "$summary_file" > "$key_file" || true
    fi

    sudo chmod a+r "$log_file" 2>/dev/null || true
    echo
    echo "Evidence saved in: $output_dir"
    echo "- $log_file"
    echo "- $pcap_file"
    echo "- $summary_file"
    echo "- $key_file"
}

on_signal() {
    exit 130
}

trap cleanup 0
trap on_signal INT TERM

cat > "$output_dir/VM_COMMANDS.txt" <<'EOF'
# Run these commands from the Ubuntu VM after netmon starts on the Pi.
PI_IP=<pi-ip>

ping -c 1 "$PI_IP"
ssh -o ConnectTimeout=3 "$PI_IP"
printf 'netmon-dns-test\n' | nc -u -w 1 "$PI_IP" 53

for p in $(seq 1 30); do
  nc -zn -w 1 "$PI_IP" "$p" >/dev/null 2>&1 &
done
wait
EOF

echo "Starting tcpdump. Generated VM commands: $output_dir/VM_COMMANDS.txt"
echo "Run the commands from the Ubuntu VM, record the LED demonstration, then press Ctrl+C here."

sudo tcpdump -ni "$interface" -w "$pcap_file" 'icmp or tcp or udp port 53' &
tcpdump_pid=$!

sudo ./netmon \
    -i "$interface" \
    -l "$log_file" \
    --gpio-chip "$gpio_chip" \
    --gpio-line "$gpio_line"
