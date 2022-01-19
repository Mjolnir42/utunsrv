# utunsrv - UDP over TLS forwarding

## UDP to TLS forwarding mode

When configured in this mode, a UDP listen socket will be opened and
received UDP data forwarded via TLS connection to specified remote
service.
The remote TLS service must use a certificate that can be validated using
the provided rootCA.

```
./utunsrv -udpsrv localhost:4739 -remote localhost:4739 -ca rootCA.crt
```

## TLS to UDP forwarding mode

When configured in this mode, a TCP listen socket will be opened offering
TLS using the configured rootCA, service certificate and key as well as
the provided SNI service name.
All data received on the TLS service will be forwarded via UDP to the
specified remote service.

```
./utunsrv -tlssrv localhost:4739 -remote server.invalid:4739 -name localhost -ca rootCA.crt -tlscert localhost.crt -tlskey localhost.key
```
