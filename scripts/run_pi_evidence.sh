#!/bin/sh
# Run netmon and tcpdump together, then preserve report-ready evidence on exit.

set -eu

usage() {
    echo "Usage: $0 -i <interface> [--gpio-line <line>] [--no-led] [--gpio-chip <path>] [--display none|tm1637] [--display-clk <line>] [--display-dio <line>] [--display-brightness <0..7>] [--output-dir <path>]" >&2
    exit 2
}

interface=""
gpio_chip="/dev/gpiochip0"
gpio_line=""
no_led=0
display="none"
display_clk=""
display_dio=""
display_brightness=3
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
        --no-led)
            no_led=1
            shift
            ;;
        --display)
            [ "$#" -ge 2 ] || usage
            display="$2"
            shift 2
            ;;
        --display-clk)
            [ "$#" -ge 2 ] || usage
            display_clk="$2"
            shift 2
            ;;
        --display-dio)
            [ "$#" -ge 2 ] || usage
            display_dio="$2"
            shift 2
            ;;
        --display-brightness)
            [ "$#" -ge 2 ] || usage
            display_brightness="$2"
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
case "$display" in
    none) ;;
    tm1637) [ -n "$display_clk" ] && [ -n "$display_dio" ] || usage ;;
    *) usage ;;
esac
case "$display_brightness" in
    [0-7]) ;;
    *) usage ;;
esac
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

# Stop the test traffic and keep filming for at least 12 seconds.
# Type 3 falls back to 3000 after the last SYN to each port expires.
# The scan includes port 22, so Type 2 may also increase.
EOF

echo "Starting tcpdump. Generated VM commands: $output_dir/VM_COMMANDS.txt"
echo "Run the commands from the Ubuntu VM, record the display/LED demonstration, then press Ctrl+C here."

sudo tcpdump -ni "$interface" -w "$pcap_file" 'icmp or tcp or udp port 53' &
tcpdump_pid=$!

set -- -i "$interface" -l "$log_file" --gpio-chip "$gpio_chip" \
    --display "$display" --display-brightness "$display_brightness"
if [ "$no_led" -eq 1 ] || [ -z "$gpio_line" ]; then
    set -- "$@" --no-led
else
    set -- "$@" --gpio-line "$gpio_line"
fi
if [ -n "$display_clk" ]; then
    set -- "$@" --display-clk "$display_clk"
fi
if [ -n "$display_dio" ]; then
    set -- "$@" --display-dio "$display_dio"
fi
sudo ./netmon "$@"
