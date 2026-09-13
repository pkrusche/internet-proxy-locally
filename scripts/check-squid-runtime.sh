#!/usr/bin/env sh
# Read-only live verification: Squid must already be running in the given mode.
set -eu
backend="${1:?expected docker or container}"
mode="${2:?expected on or off}"
case "$backend" in docker|container) ;; *) exit 2 ;; esac
case "$mode" in on|off) ;; *) exit 2 ;; esac

# Explicit user is essential: the image bootstrap may have been started as root.
"$backend" exec --user squid internet-proxy-squid sh -ec '
    squid_uid="$(id -u squid)"
    squid_gid="$(id -g squid)"
    [ "$squid_uid" -ne 0 ] && [ "$squid_gid" -ne 0 ] || exit 1
    [ "$(id -u)" = "$squid_uid" ]
    uid_seen=0
    gid_seen=0
    groups_seen=0
    while read -r field real effective saved filesystem; do
        case "$field" in
            Uid:)
                [ "$real:$effective:$saved:$filesystem" = "$squid_uid:$squid_uid:$squid_uid:$squid_uid" ] || exit 1
                uid_seen=1 ;;
            Gid:)
                [ "$real:$effective:$saved:$filesystem" = "$squid_gid:$squid_gid:$squid_gid:$squid_gid" ] || exit 1
                gid_seen=1 ;;
            Groups:)
                # Runtime USER squid may have no supplementary groups. The
                # su-exec path has just the primary group; neither needs extras.
                case "$real:$effective:$saved:$filesystem" in
                    :::|"$squid_gid":::) ;; *) exit 1 ;;
                esac
                groups_seen=1 ;;
        esac
    done < /proc/1/status
    [ "$uid_seen:$gid_seen:$groups_seen" = 1:1:1 ]

    if [ "$1" = on ]; then
        [ "$(stat -f -c %T /dev/shm)" = tmpfs ]
        [ "$(stat -c %a:%u:%g /dev/shm/ipl-squid-ca)" = "500:$squid_uid:$squid_gid" ]
        for file in ca.pem ca-key.pem; do
            [ -s "/dev/shm/ipl-squid-ca/$file" ]
            [ "$(stat -c %a:%u:%g "/dev/shm/ipl-squid-ca/$file")" = "400:$squid_uid:$squid_gid" ]
            [ ! -r "/run/ipl-ca/$file" ]
        done
    else
        [ ! -e /dev/shm/ipl-squid-ca ]
    fi
    echo "Squid: non-root real/effective/saved IDs and TLS $1 CA staging verified"
' sh "$mode"
