#!/usr/bin/env sh
# Read-only live verification: Squid must already be running in the given mode.
set -eu
backend="${1:?expected docker or container}"
mode="${2:?expected on or off}"
case "$backend" in docker|container) ;; *) exit 2 ;; esac
case "$mode" in on|off) ;; *) exit 2 ;; esac

# Explicit user is essential: the image bootstrap may have been started as root.
"$backend" exec --user squid internet-proxy-squid sh -ec '
    phase="resolve Squid identity"
    trap '\''rc=$?; if [ "$rc" -ne 0 ]; then echo "Squid runtime verification failed: $phase (exit $rc)" >&2; fi'\'' EXIT
    equal() {
        if [ "$2" != "$3" ]; then
            echo "Squid: $1: expected [$3], got [$2]" >&2
            exit 1
        fi
    }
    squid_uid="$(id -u squid)"
    squid_gid="$(id -g squid)"
    echo "Squid: expected uid=$squid_uid gid=$squid_gid; verifier uid=$(id -u); TLS=$1"
    [ "$squid_uid" -ne 0 ] && [ "$squid_gid" -ne 0 ] || exit 1
    equal "verifier UID" "$(id -u)" "$squid_uid"
    phase="PID 1 identity and supplementary groups"
    uid_seen=0
    gid_seen=0
    groups_seen=0
    while read -r field real effective saved filesystem; do
        case "$field" in
            Uid:)
                equal "PID 1 UIDs (real/effective/saved/filesystem)" "$real:$effective:$saved:$filesystem" "$squid_uid:$squid_uid:$squid_uid:$squid_uid"
                uid_seen=1 ;;
            Gid:)
                equal "PID 1 GIDs (real/effective/saved/filesystem)" "$real:$effective:$saved:$filesystem" "$squid_gid:$squid_gid:$squid_gid:$squid_gid"
                gid_seen=1 ;;
            Groups:)
                # Runtime USER squid may have no supplementary groups. The
                # su-exec path has just the primary group; neither needs extras.
                case "$real:$effective:$saved:$filesystem" in
                    :::|"$squid_gid":::) ;;
                    *) echo "Squid: unexpected supplementary groups [$real $effective $saved $filesystem]; expected empty or $squid_gid" >&2; exit 1 ;;
                esac
                groups_seen=1 ;;
        esac
    done < /proc/1/status
    equal "UID/GID/Groups fields present" "$uid_seen:$gid_seen:$groups_seen" 1:1:1

    if [ "$1" = on ]; then
        phase="tmpfs CA directory"
        equal "CA filesystem" "$(stat -f -c %T /dev/shm)" tmpfs
        equal "CA directory mode/uid/gid" "$(stat -c %a:%u:%g /dev/shm/ipl-squid-ca)" "500:$squid_uid:$squid_gid"
        for file in ca.pem ca-key.pem; do
            phase="staged $file exists and is nonempty"
            [ -s "/dev/shm/ipl-squid-ca/$file" ]
            equal "$file mode/uid/gid" "$(stat -c %a:%u:%g "/dev/shm/ipl-squid-ca/$file")" "400:$squid_uid:$squid_gid"
            phase="original $file mount must be inaccessible to Squid"
            [ ! -r "/run/ipl-ca/$file" ]
        done
    else
        phase="TLS off must not have a staged CA directory"
        [ ! -e /dev/shm/ipl-squid-ca ]
    fi
    echo "Squid: non-root real/effective/saved IDs and TLS $1 CA staging verified"
' sh "$mode"
