# WWW::OpenBao

Perl HTTP client for [OpenBao](https://openbao.org/) and HashiCorp Vault — KV
v2 secrets, health/init/unseal, enable-engine, and Kubernetes ServiceAccount
auth.

## Synopsis

```perl
use WWW::OpenBao;

my $bao = WWW::OpenBao->new(
  endpoint => $ENV{OPENBAO_ADDR}  // 'http://127.0.0.1:8200',
  token    => $ENV{OPENBAO_TOKEN} // '',
  kv_mount => 'secret',
);

$bao->write_secret('app/db',    { user => 'app', pass => 'hunter2' });
my $creds = $bao->read_secret('app/db');       # { user => 'app', ... }
my $old   = $bao->read_secret('app/db', version => 1);
my $meta  = $bao->read_secret_metadata('app/db');   # version, created_time, ...

my @keys  = @{ $bao->list_secrets('app/') };
$bao->delete_secret('app/db');
```

## Deleting: three levels

```perl
$bao->soft_delete_secret('app/db');        # level 1: latest version, reversible
$bao->soft_delete_secret('app/db', 2, 3);  # level 1: named versions
$bao->undelete_secret('app/db', 2, 3);     # reverse a soft delete
$bao->destroy_secret('app/db', 1);         # level 2: version bytes gone for good
$bao->delete_secret('app/db');             # level 3: key + every version, irreversible
```

## Kubernetes ServiceAccount login

```perl
$bao->login_k8s( role => 'my-app' );   # sets $bao->token
```

Default JWT path is `/var/run/secrets/kubernetes.io/serviceaccount/token`;
override via `jwt => $my_token`. Set `k8s_auth_mount` when the auth method is
not mounted at `kubernetes`.

## Bootstrap helpers

```perl
$bao->init;                               # first-time init (dev only)
$bao->unseal($key);                       # unseal with a key share
$bao->enable_engine('goldmine', 'kv-v2'); # mount a named KV engine
$bao->health;                             # /v1/sys/health
```

## TLS

For an `https://` endpoint the server certificate is always verified — the
client sets this itself, independent of the installed HTTP::Tiny version and
of `PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT`.

```perl
WWW::OpenBao->new( endpoint => $url, ssl_ca_file => '/etc/ssl/private-ca.pem' ); # private CA
WWW::OpenBao->new( endpoint => $url, verify_ssl  => 0 );  # dev only: accepts any certificate
```

`ssl_ca_file` keeps verification on and is the right choice for a server
signed by your own CA. `verify_ssl => 0` exposes the token and every secret to
anyone who can intercept the connection. HTTPS needs `IO::Socket::SSL` and
`Net::SSLeay`, which are not dependencies of this distribution.

## Error handling

Every request goes through one shared seam: a non-2xx response `croak`s with
the status and response body — except `404`, which never croaks and comes
back as a soft miss:

- `read_secret` and `read_secret_metadata` return `undef` (KV v2 answers 404
  for an absent path *and* a soft-deleted version, so `undef` means "no
  readable value", not "never existed")
- `list_secrets` returns an empty arrayref
- `secret_exists` returns false — only on 404; a 403 croaks
- `login_k8s` returns an empty hashref and leaves `token` undefined
- every other method returns `undef`

`health` never croaks: it returns the health hashref for any reachable server
(sealed, standby and uninitialised included) and `undef` when there is no
usable answer.

## License

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
