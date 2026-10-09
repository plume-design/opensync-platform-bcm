#!/bin/sh

#################################################################
# This script is called by debug_monitor to parse the trap reason
# and reboot the system when a firmware trap is detected on any of
# the wl interfaces.
#
# Use the following command to simulate a firmware trap for testing:
# wl -i wlX bus:disconnect 99
# where wlX is the dongle interface

# Scan the bootup messages for a corrupted firmware image download. When the
# firmware image is reported as corrupted, echo a marker that gets appended to
# the trap reason so the reboot reason reflects the FW corruption.
iscorrupted() {
    if grep -q "dhdpcie_hybridfw_download: Downloaded image is corrupted\." /tmp/bootupmessages 2>/dev/null; then
        printf " | FW corrupted"
    fi
}

RR=""

for path in /sys/class/net/wl*; do
    [ -e "$path" ] || continue

    radio=${path##*/}

    case "$radio" in
        *.*) continue ;;
    esac

    # Expected console output example:
    # TRAP 4(aeb10): pc 23dc, lr 7147, sp aeb68, cpsr 880001d3, spsr 88000033
    # Formatted as: fw-trap on wlX [type 0x4 @ epc 0x23dc]
    line="$(dhd -i "$radio" consoledump 2>/dev/null | \
        awk -v radio="$radio" '
            /TRAP/ {
                type = $2
                sub(/\(.*/, "", type)

                epc = ""
                for (i = 1; i < NF; i++) {
                    if ($i == "pc") {
                        epc = $(i + 1)
                        sub(/,/, "", epc)
                        break
                    }
                }

                if (type != "" && epc != "")
                    printf "fw-trap on %s [type 0x%s @ epc 0x%s]", radio, type, epc

                exit
            }
        ')"

    [ -z "$line" ] && continue

    if [ -n "$RR" ]; then
        RR="${RR}; ${line}"
    else
        RR="$line"
    fi
done

[ -z "$RR" ] && RR="fw-trap detected"

# Append the FW-corrupted marker (if any) to the final reason so it is reported
# in every case, including the default "fw-trap detected" fallback.
RR="${RR}$(iscorrupted)"

/sbin/reboot -Rtype=crash -Rreason="$RR"

