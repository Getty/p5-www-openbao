# WWW::OpenBao

Perl HTTP client for [OpenBao](https://openbao.org/) and HashiCorp Vault — KV
v2 secrets, health/init/unseal, enable-engine, Kubernetes ServiceAccount and
AppRole auth, ACL policies, token roles, the database secrets engine and
leases.

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

## Policies, AppRole and token roles

```perl
$bao->write_policy('app', $hcl);                    # create / replace
my $text = $bao->read_policy('app');                # undef if absent
$bao->delete_policy('app');

$bao->enable_approle;                               # at approle_auth_mount
$bao->ensure_approle_role('app', token_policies => ['app']);
my $role_id   = $bao->approle_role_id('app');
my $secret_id = $bao->approle_secret_id('app');     # fresh each call
$bao->login_approle( role_id => $role_id, secret_id => $secret_id );  # sets token

$bao->enable_auth('userpass', 'userpass');          # any auth method
$bao->ensure_token_role('batch', allowed_policies => ['app']);
```

## Database engine and leases

```perl
$bao->enable_engine('database', 'database');        # mount at database_mount
$bao->configure_database('pg', plugin_name => 'postgresql-database-plugin',
  connection_url => '...', allowed_roles => ['app'], username => $u, password => $p);
$bao->database_role('app', db_name => 'pg', creation_statements => [$sql],
  default_ttl => '1h');
my $c = $bao->database_credentials('app');   # username, password, lease_id, lease_duration, renewable
$bao->renew_lease($c->{lease_id}, increment => 3600);
$bao->revoke_lease($c->{lease_id});
$bao->rotate_root('pg');                     # only the server knows the root password afterwards
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
- `login_k8s` croaks (like `login_approle`) and leaves `token` untouched
- `read_policy`, `approle_role_id`, `approle_secret_id` and
  `database_credentials` return `undef`

Writes are the exception: `write_secret`, `delete_secret`,
`soft_delete_secret`, `undelete_secret`, `destroy_secret`, `init`, `unseal`,
`enable_engine`, `enable_auth`, `enable_approle`, the policy writes/deletes,
the AppRole and token role writes, the database and lease calls `croak` on a
404 too — a mistyped mount must not look like a stored secret.

`health` never croaks: it returns the health hashref for any reachable server
(sealed, standby and uninitialised included) and `undef` when there is no
usable answer.

## License

This library is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.
