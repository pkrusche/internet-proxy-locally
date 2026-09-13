#!/bin/sh
# Only this bootstrap handles the host-owned key as root. Squid never does.
set -eu

[ "$#" -gt 0 ] || { echo "error: missing Squid command" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    squid_uid="$(id -u squid)"
    squid_gid="$(id -g squid)"
    if [ "$squid_uid" -eq 0 ] || [ "$squid_gid" -eq 0 ]; then
        echo "error: Squid must have a non-root user and group" >&2
        exit 1
    fi
    # Docker and Apple container supply /dev/shm as tmpfs. Refuse a disk-backed
    # substitute: private material must not enter the container's writable layer.
    if [ "$(stat -f -c %T /dev/shm)" != tmpfs ]; then
        echo "error: Squid CA staging requires tmpfs at /dev/shm" >&2
        exit 1
    fi

    umask 077
    # mkdir fails if this path already exists, including as a symlink. Never
    # follow or overwrite a pre-existing staging directory.
    mkdir -m 0700 /dev/shm/ipl-squid-ca
    cp /run/ipl-ca/ca.pem /dev/shm/ipl-squid-ca/ca.pem
    cp /run/ipl-ca/ca-key.pem /dev/shm/ipl-squid-ca/ca-key.pem
    chmod 0400 /dev/shm/ipl-squid-ca/ca.pem /dev/shm/ipl-squid-ca/ca-key.pem
    chmod 0500 /dev/shm/ipl-squid-ca
    chown "$squid_uid:$squid_gid" /dev/shm/ipl-squid-ca/ca.pem /dev/shm/ipl-squid-ca/ca-key.pem /dev/shm/ipl-squid-ca

    # Squid reopens /dev/stdout and /dev/stderr instead of only writing to
    # inherited descriptors. Runtime pipes created for this root bootstrap
    # would otherwise reject those opens after su-exec. Change only the two
    # inherited pipes, never an arbitrary redirected file or device.
    for fd in 1 2; do
        pipe="/proc/self/fd/$fd"
        if [ ! -p "$pipe" ]; then
            echo "error: Squid logging requires a runtime pipe on fd $fd" >&2
            exit 1
        fi
        chown "$squid_uid:$squid_gid" "$pipe" || {
            echo "error: cannot give Squid ownership of logging pipe fd $fd" >&2
            exit 1
        }
    done

    # setgroups/setgid/setuid + exec: no saved root UID, no root parent, and
    # Squid receives container signals directly. Never launch it if copying,
    # permissions, or the privilege drop fails.
    exec su-exec "$squid_uid:$squid_gid" "$@"
fi

# TLS off uses the image's USER squid and needs no root bootstrap or CA copy.
exec "$@"
