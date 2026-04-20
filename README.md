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

my @keys  = @{ $bao->list_secrets('app/') };
$bao->delete_secret('app/db');
```

## Kubernetes ServiceAccount login

```perl
$bao->login_k8s( role => 'my-app' );   # sets $bao->token
```

Default JWT path is `/var/run/secrets/kubernetes.io/serviceaccount/token`;
override via `jwt => $my_token`.

## Bootstrap helpers

```perl
$bao->init;                               # first-time init (dev only)
$bao->unseal($key);                       # unseal with a key share
$bao->enable_engine('goldmine', 'kv-v2'); # mount a named KV engine
$bao->health;                             # /v1/sys/health
```

## Error handling

All methods `croak` on non-2xx responses (except `read_secret`, which returns
`undef` on 404 so callers can treat "secret not found" as a soft miss).

## License

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
