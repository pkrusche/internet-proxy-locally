# Security policy

Version 0.1 receives security fixes while it is the latest release. Report a
vulnerability privately through the repository host's security-advisory form;
do not include secrets in a public issue. We aim to acknowledge reports within
five business days and will coordinate disclosure after a fix is available.

The proxy is one layer, not a hostile-client sandbox boundary. Clients can
ignore proxy environment variables unless direct egress is separately blocked.
Users who can edit trusted policy/code or access the container socket can alter
enforcement. TLS interception makes the proxy a trusted CA and does not, by
itself, prevent uploads to allowed destinations.
