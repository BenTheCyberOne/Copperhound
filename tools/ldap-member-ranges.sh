#!/usr/bin/env bash
# Fetch the remaining `member` ranges of large groups in an LDIF dump.
#
# Active Directory returns at most MaxValRange (1500 by default) values of a
# multi-valued attribute per read; ldapsearch then writes
# `member;range=0-1499: …` and stops. This script finds every entry of DUMP
# that holds such a first range, fetches the rest with ranged base reads
# (`member;range=1500-*`, …) and writes them as continuation entries:
#
#   dn:: <base64 DN>
#   member;range=1500-2999: CN=…
#
# Drop the output next to the dump (same upload / directory): CopperHound adds
# continuation entries to the group's membership (see docs/DATA.md "Importing
# multiple dumps").
#
# Usage:
#   tools/ldap-member-ranges.sh DUMP.ldif [ldapsearch connection options…] > DUMP-member-ranges.ldif
# Example:
#   tools/ldap-member-ranges.sh corp-domain.ldif -H ldap://dc01.corp.local -Y GSSAPI > corp-member-ranges.ldif
#   tools/ldap-member-ranges.sh corp-domain.ldif -H ldap://dc01 -x -D user@corp.local -W > corp-member-ranges.ldif
set -euo pipefail

if [ $# -lt 1 ] || [ ! -f "$1" ]; then
    sed -n '2,22p' "$0" >&2
    exit 2
fi
dump=$1
shift

# Unfold LDIF continuation lines, then print "<dn>\t<last index of range 0>"
# for entries carrying `member;range=0-N` (N numeric: the read was truncated).
first_ranges() {
    tr -d '\r' < "$dump" | awk '
        /^ / { line = line substr($0, 2); next }
        { if (started) print line; line = $0; started = 1 }
        END { if (started) print line }
    ' | awk '
        /^dn:: / { dn = "b64:" substr($0, 6); next }
        /^dn: /  { dn = substr($0, 5); next }
        /^$/     { dn = ""; next }
        {
            l = tolower($0)
            if (dn != "" && match(l, /^member;range=0-[0-9]+:/)) {
                spec = substr(l, 14, RLENGTH - 14)          # "0-1499"
                split(spec, r, "-")
                if (!(dn in seen)) { seen[dn] = 1; print dn "\t" r[2] }
            }
        }
    '
}

b64() { printf '%s' "$1" | base64 | tr -d '\n'; }

n=0
while IFS=$'\t' read -r dn last; do
    [ -n "$dn" ] || continue
    case $dn in b64:*) dn=$(printf '%s' "${dn#b64:}" | base64 -d) ;; esac
    start=$((last + 1))
    while :; do
        out=$(ldapsearch "$@" -LLL -o ldif-wrap=no -b "$dn" -s base '(objectClass=*)' "member;range=${start}-*" | tr -d '\r')
        hdr=$(printf '%s\n' "$out" | grep -io '^member;range=[0-9]*-[0-9*]*' | head -n 1 || true)
        [ -n "$hdr" ] || break
        printf 'dn:: %s\n' "$(b64 "$dn")"
        printf '%s\n' "$out" | grep -i '^member;range='
        printf '\n'
        hi=${hdr##*-}
        [ "$hi" != "*" ] || break
        start=$((hi + 1))
    done
    n=$((n + 1))
done < <(first_ranges)
echo "ldap-member-ranges: completed $n group(s)" >&2
