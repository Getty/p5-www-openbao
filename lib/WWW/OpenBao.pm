package WWW::OpenBao;
# ABSTRACT: HTTP client for OpenBao / HashiCorp Vault API
our $VERSION = '0.004';
use Moo;
use HTTP::Tiny;
use JSON::MaybeXS;
use Carp qw(croak);
use namespace::clean;

has endpoint       => (is => 'ro', required => 1);
has token          => (is => 'rw', default => sub { '' });
has kv_mount       => (is => 'ro', default => sub { 'secret' });
has k8s_auth_mount => (is => 'ro', default => sub { 'kubernetes' });
has approle_auth_mount => (is => 'ro', default => sub { 'approle' });
has database_mount  => (is => 'ro', default => sub { 'database' });
has verify_ssl     => (is => 'ro', default => sub { 1 });
has ssl_ca_file    => (is => 'ro');
has _http          => (is => 'lazy');

# verify_SSL is always passed explicitly: HTTP::Tiny's own default was "off"
# before 0.083 and PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT=1 turns it off on
# newer versions, and neither may decide whether a token or a secret travels
# over an unverified connection. Only a defined false verify_ssl switches it
# off — an undef (e.g. a missing config key passed through) keeps it on.
sub _build__http {
  my ($self) = @_;
  my %ssl;
  $ssl{SSL_ca_file} = $self->ssl_ca_file if defined $self->ssl_ca_file;
  return HTTP::Tiny->new(
    timeout     => 10,
    verify_SSL  => ($self->verify_ssl // 1) ? 1 : 0,
    SSL_options => \%ssl,
  );
}

# KV v2 paths. The secret path is percent-escaped (UTF-8 bytes, RFC 3986
# unreserved characters kept) with "/" left alone, so a key containing a
# space, ?, # or % reaches the server as a path, not as a query or fragment.
# A caller that already passes a pre-escaped path would be escaped twice.
sub _kv_escape {
  my ($p) = @_;
  utf8::encode($p) if utf8::is_utf8($p);
  $p =~ s{([^A-Za-z0-9\-._~/])}{sprintf '%%%02X', ord $1}ge;
  return $p;
}
sub _kv_path          { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/data/"       . _kv_escape($p) }
sub _kv_metadata_path { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/metadata/"   . _kv_escape($p) }
sub _kv_delete_path   { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/delete/"     . _kv_escape($p) }
sub _kv_undelete_path { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/undelete/"   . _kv_escape($p) }
sub _kv_destroy_path  { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/destroy/"    . _kv_escape($p) }

# Core HTTP
sub _request {
  my ($self, $method, $path, $body, $strict) = @_;
  (my $base = $self->endpoint) =~ s{/+\z}{};
  my $url = $base . '/' . $path;
  my %opts = (headers => {
    'X-Vault-Token' => $self->token,
  });
  if ($body) {
    $opts{content} = encode_json($body);
    $opts{headers}{'Content-Type'} = 'application/json';
  }
  my $resp = $self->_http->request($method, $url, \%opts);
  return undef if $resp->{status} == 404 && !$strict;
  croak "OpenBao $method $path: $resp->{status} $resp->{content}"
    unless $resp->{success};
  return {} unless $resp->{content};
  my $data = eval { decode_json($resp->{content}) };
  croak "OpenBao $method $path: $resp->{status} response is not JSON: "
    . substr($resp->{content}, 0, 200)
    unless defined $data;
  return $data;
}

# A write whose route answers 404 (mistyped mount, KV v1, no such engine) did
# not happen; returning undef would let the caller carry on, so a 404 croaks
# like any other non-2xx. Reads keep the soft miss via plain _request.
sub _write {
  my ($self, $method, $path, $body) = @_;
  return $self->_request($method, $path, $body, 1);
}

# KV v2: GET data/<path>, latest version by default; version => $n reads an
# older version via ?version=N. defined (not truthy) so an explicit
# version => 0 is honoured as a real argument, not dropped as "none".
sub _kv_read {
  my ($self, $path, %args) = @_;
  my $kv_path = $self->_kv_path($path);
  $kv_path .= '?version=' . $args{version} if defined $args{version};
  return $self->_request('GET', $kv_path);
}

# KV v2: read secret data (data.data)
sub read_secret {
  my ($self, $path, %args) = @_;
  my $resp = $self->_kv_read($path, %args);
  return undef unless $resp;
  return $resp->{data}{data};
}

# KV v2: read the metadata (version / created_time / destroyed / ...) that
# rides along the same data/ read. Separate entry point on purpose so
# read_secret keeps returning the bare data.data hashref consumers depend on.
sub read_secret_metadata {
  my ($self, $path, %args) = @_;
  my $resp = $self->_kv_read($path, %args);
  return undef unless $resp;
  return $resp->{data}{metadata};
}

# KV v2: write secret data
sub write_secret {
  my ($self, $path, $data) = @_;
  return $self->_write('POST', $self->_kv_path($path), { data => $data });
}

# KV v2: delete secret (all versions + metadata) — ladder level 3, irreversible
sub delete_secret {
  my ($self, $path) = @_;
  return $self->_write('DELETE', $self->_kv_metadata_path($path));
}

# KV v2 delete ladder level 1 (reversible soft delete). Without versions,
# soft-deletes the latest version via DELETE data/; with a version list,
# soft-deletes exactly those versions via POST delete/. Reverse with
# undelete_secret.
sub soft_delete_secret {
  my ($self, $path, @versions) = @_;
  return $self->_write('POST', $self->_kv_delete_path($path), { versions => \@versions })
    if @versions;
  return $self->_write('DELETE', $self->_kv_path($path));
}

# KV v2: restore soft-deleted versions (reverses soft_delete_secret)
sub undelete_secret {
  my ($self, $path, @versions) = @_;
  croak "undelete_secret requires at least one version" unless @versions;
  return $self->_write('POST', $self->_kv_undelete_path($path), { versions => \@versions });
}

# KV v2 delete ladder level 2 (irreversible): permanently destroy named
# versions via PUT destroy/. The version bytes are gone; key and metadata stay.
sub destroy_secret {
  my ($self, $path, @versions) = @_;
  croak "destroy_secret requires at least one version" unless @versions;
  return $self->_write('PUT', $self->_kv_destroy_path($path), { versions => \@versions });
}

# KV v2: list secrets at path
sub list_secrets {
  my ($self, $path) = @_;
  my $resp = $self->_request('LIST', $self->_kv_metadata_path($path));
  return [] unless $resp;
  return $resp->{data}{keys} // [];
}

# KV v2: check if secret exists without fetching data. Only a 404 (absent
# path) is a soft "no"; a 403 (policy forbids a path that may well exist) and
# any other non-2xx propagate via _request's croak, so callers can tell
# "not allowed to see" apart from "not there".
sub secret_exists {
  my ($self, $path) = @_;
  return defined $self->_request('GET', $self->_kv_metadata_path($path));
}

# Auth: Kubernetes ServiceAccount login
sub login_k8s {
  my ($self, %args) = @_;
  my $role = $args{role} // croak "login_k8s requires 'role'";
  my $jwt  = $args{jwt}  // _read_sa_token();
  my $resp = $self->_request('POST', 'v1/auth/' . $self->k8s_auth_mount . '/login', {
    role => $role, jwt => $jwt,
  });
  croak "login_k8s: auth method not mounted at " . $self->k8s_auth_mount
    unless $resp;
  $self->token($resp->{auth}{client_token});
  return $resp->{auth};
}

sub _read_sa_token {
  my $path = '/var/run/secrets/kubernetes.io/serviceaccount/token';
  open my $fh, '<', $path or croak "Cannot read SA token: $!";
  local $/;
  return <$fh>;
}

# Sys: health check. standbyok/sealedcode/uninitcode flatten the operational
# states that otherwise answer with a non-2xx status (standby 429, sealed 503,
# uninitialised 501) to a 200, so _request decodes the body instead of
# croaking — the caller reads the state out of the returned hashref
# (initialized, sealed, standby, ...). perfstandbyok is Vault's parameter for
# the performance-standby state; OpenBao does not know it and ignores it
# without complaint. The eval still maps a genuinely unreachable server
# (network error, or non-2xx despite the codes) to undef, so "no answer at
# all" stays distinct from any reported state.
sub health {
  my ($self) = @_;
  return eval {
    $self->_request('GET',
      'v1/sys/health?standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200')
  };
}

# Sys: initialize vault (first time)
sub init {
  my ($self, %args) = @_;
  my $shares    = $args{secret_shares}    // 1;
  my $threshold = $args{secret_threshold} // 1;
  return $self->_write('POST', 'v1/sys/init', {
    secret_shares => $shares, secret_threshold => $threshold,
  });
}

# Sys: unseal
sub unseal {
  my ($self, $key) = @_;
  return $self->_write('POST', 'v1/sys/unseal', { key => $key });
}

# Sys: enable secrets engine
sub enable_engine {
  my ($self, $path, $type) = @_;
  return $self->_write('POST', "v1/sys/mounts/$path", { type => $type });
}

# Sys: enable an auth method. %opts ride along in the body (description,
# config, ...); type is always the one named here.
sub enable_auth {
  my ($self, $path, $type, %opts) = @_;
  return $self->_write('POST', "v1/sys/auth/$path", { %opts, type => $type });
}

# Sys: ACL policies
sub write_policy {
  my ($self, $name, $hcl) = @_;
  croak "write_policy requires a policy name" unless defined $name && length $name;
  croak "write_policy requires the policy text" unless defined $hcl && length $hcl;
  return $self->_write('PUT', "v1/sys/policies/acl/$name", { policy => $hcl });
}

sub read_policy {
  my ($self, $name) = @_;
  my $resp = $self->_request('GET', "v1/sys/policies/acl/$name");
  return $resp ? $resp->{data}{policy} : undef;
}

sub delete_policy {
  my ($self, $name) = @_;
  return $self->_write('DELETE', "v1/sys/policies/acl/$name");
}

# Auth: AppRole
sub _approle_path { my ($self, $p) = @_; 'v1/auth/' . $self->approle_auth_mount . "/$p" }

sub enable_approle {
  my ($self, %opts) = @_;
  return $self->enable_auth($self->approle_auth_mount, 'approle', %opts);
}

sub ensure_approle_role {
  my ($self, $name, %opts) = @_;
  return $self->_write('POST', $self->_approle_path("role/$name"), { %opts });
}

sub approle_role_id {
  my ($self, $name) = @_;
  my $resp = $self->_request('GET', $self->_approle_path("role/$name/role-id"));
  return $resp ? $resp->{data}{role_id} : undef;
}

sub approle_secret_id {
  my ($self, $name, %opts) = @_;
  my $resp = $self->_request('POST', $self->_approle_path("role/$name/secret-id"), { %opts });
  return $resp ? $resp->{data}{secret_id} : undef;
}

sub login_approle {
  my ($self, %args) = @_;
  my $role_id   = $args{role_id}   // croak "login_approle requires 'role_id'";
  my $secret_id = $args{secret_id} // croak "login_approle requires 'secret_id'";
  my $resp = $self->_request('POST', $self->_approle_path('login'), {
    role_id => $role_id, secret_id => $secret_id,
  });
  croak "login_approle: auth method not mounted at " . $self->approle_auth_mount
    unless $resp;
  $self->token($resp->{auth}{client_token});
  return $resp->{auth};
}

# Auth: token roles
sub ensure_token_role {
  my ($self, $name, %opts) = @_;
  return $self->_write('POST', "v1/auth/token/roles/$name", { %opts });
}

# Database secrets engine: connections, roles, dynamic credentials, rotation
sub _database_path { my ($self, $p) = @_; 'v1/' . $self->database_mount . "/$p" }

sub configure_database {
  my ($self, $name, %opts) = @_;
  return $self->_write('POST', $self->_database_path("config/$name"), { %opts });
}

sub database_role {
  my ($self, $name, %opts) = @_;
  return $self->_write('POST', $self->_database_path("roles/$name"), { %opts });
}

sub database_credentials {
  my ($self, $name) = @_;
  my $resp = $self->_request('GET', $self->_database_path("creds/$name"));
  return undef unless $resp;
  return { %{ $resp->{data} },
    lease_id       => $resp->{lease_id},
    lease_duration => $resp->{lease_duration},
    renewable      => $resp->{renewable} };
}

sub rotate_root {
  my ($self, $name) = @_;
  return $self->_write('POST', $self->_database_path("rotate-root/$name"));
}

# Sys: leases
sub renew_lease {
  my ($self, $lease_id, %opts) = @_;
  croak "renew_lease requires a lease id" unless defined $lease_id && length $lease_id;
  return $self->_write('PUT', 'v1/sys/leases/renew', { %opts, lease_id => $lease_id });
}

sub revoke_lease {
  my ($self, $lease_id) = @_;
  croak "revoke_lease requires a lease id" unless defined $lease_id && length $lease_id;
  return $self->_write('PUT', 'v1/sys/leases/revoke', { lease_id => $lease_id });
}

1;

__END__

=head1 SYNOPSIS

  use WWW::OpenBao;

  my $bao = WWW::OpenBao->new(
    endpoint => $ENV{OPENBAO_ADDR}  // 'http://127.0.0.1:8200',
    token    => $ENV{OPENBAO_TOKEN} // '',
    kv_mount => 'secret',
  );

  $bao->write_secret('app/db', { user => 'app', pass => 'hunter2' });
  my $creds = $bao->read_secret('app/db');
  my $meta  = $bao->read_secret_metadata('app/db');  # version, created_time, ...
  my $keys  = $bao->list_secrets('app/');
  $bao->delete_secret('app/db');

  $bao->login_k8s( role => 'my-app' );  # sets $bao->token

  # bootstrap with a root token, then log in as an AppRole
  $bao->write_policy('app', 'path "secret/data/app/*" { capabilities = ["read"] }');
  $bao->enable_approle;
  $bao->ensure_approle_role('app', token_policies => ['app']);
  my $role_id   = $bao->approle_role_id('app');
  my $secret_id = $bao->approle_secret_id('app');
  $bao->login_approle( role_id => $role_id, secret_id => $secret_id );

  # dynamic database credentials and their lease
  my $db = $bao->database_credentials('app');  # username, password, lease_id, ...
  $bao->revoke_lease( $db->{lease_id} );

=head1 DESCRIPTION

L<WWW::OpenBao> is a minimal HTTP client for L<OpenBao|https://openbao.org/>
and HashiCorp Vault. It covers the day-to-day surface used by application
code: KV v2 secret read/write/list/delete, Kubernetes ServiceAccount and
AppRole login, and the C<sys/*> and auth calls needed to bootstrap a setup:
C<health>, C<init>, C<unseal>, C<enable_engine>, C<enable_auth>, ACL policies,
AppRole and token roles, the database secrets engine (dynamic credentials) and
lease renew/revoke.

It is intentionally small — no caching and no automatic lease renewal; the
caller decides when to renew. If you need more, reach for a heavier client; if
you just want to talk to Vault/OpenBao from Perl, this is enough.

Every request goes through one shared seam, and its error contract applies to
every method: a non-2xx response C<croak>s with the status and response body,
except C<404>, which is never a C<croak>. A C<404> comes back as a soft miss:

=over 4

=item * L</read_secret> and L</read_secret_metadata> return C<undef>. KV v2
answers C<404> both for an absent path and for a soft-deleted version, so
C<undef> means "no readable value", not "never existed".

=item * L</list_secrets> returns an empty arrayref.

=item * L</secret_exists> returns false. Only a C<404> does that; a C<403>
(permission denied) croaks like any other non-2xx.

=item * L</read_policy>, L</approle_role_id>, L</approle_secret_id> and
L</database_credentials> return C<undef> for a missing policy, role or
database role.

=item * L</login_k8s> croaks instead, like L</login_approle>: an unmounted
auth method must not look like a login, and L</token> stays as it was.

=back

Writes are the exception to the soft miss: L</write_secret>,
L</delete_secret>, L</soft_delete_secret>, L</undelete_secret>,
L</destroy_secret>, L</init>, L</unseal>, L</enable_engine>,
L</enable_auth>, L</enable_approle>, the policy writes and deletes, the AppRole
and token role writes, the database and lease calls C<croak> on a C<404> like
on any other non-2xx. OpenBao answers C<404> (C<no handler for route>) for a
mistyped mount, and a write that did not happen must not look like one that
did.

L</health> is the one method that never croaks: it returns C<undef> whenever
the server gives no usable answer, see there.

For an C<https://> L</endpoint> the server certificate is always verified,
see L</verify_ssl> and L</ssl_ca_file>. HTTPS itself needs L<IO::Socket::SSL>
and L<Net::SSLeay>, which L<HTTP::Tiny> loads on demand; they are not
dependencies of this distribution, so a plain C<http://> setup installs
without them.

=attr endpoint

Required. Base URL of the Vault/OpenBao server, e.g.
C<http://127.0.0.1:8200>. A trailing slash is ignored.

=attr token

Vault token used for the C<X-Vault-Token> header. Writable — L</login_k8s>
overwrites it on success.

=attr kv_mount

Mount path of the KV v2 engine. Defaults to C<secret>.

=attr k8s_auth_mount

Mount path of the Kubernetes auth method. Defaults to C<kubernetes>, the
OpenBao/Vault default. Set it when the method is mounted elsewhere — e.g.
C<k8s_auth_mount =E<gt> 'kubernetes-prod'> makes L</login_k8s> post to
C<v1/auth/kubernetes-prod/login>.


=attr approle_auth_mount

Mount path of the AppRole auth method. Defaults to C<approle>. Used by
L</enable_approle>, L</ensure_approle_role>, L</approle_role_id>,
L</approle_secret_id> and L</login_approle>.

=attr database_mount

Mount path of the database secrets engine. Defaults to C<database>. Used by
L</configure_database>, L</database_role>, L</database_credentials> and
L</rotate_root>.

=attr verify_ssl

Whether the server certificate of an C<https://> L</endpoint> is verified.
Defaults to true. The value is handed to L<HTTP::Tiny> explicitly, so neither
an L<HTTP::Tiny> older than 0.083 (which did not verify by default) nor
C<PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT> in the environment changes it.

  verify_ssl => 0,   # dev server with a self-signed certificate

C<verify_ssl =E<gt> 0> turns the check off: any certificate is accepted, so
whoever can intercept the connection reads the token and every secret that is
sent or fetched. It is meant for a throwaway dev server and nothing else; for
a server whose certificate comes from a private CA use L</ssl_ca_file>, which
keeps verification on. Only a defined false value switches it off — an
C<undef> (say, a missing config key passed through) leaves verification on.

=attr ssl_ca_file

Optional. Path to a PEM file with the CA certificate(s) the server certificate
is verified against — for an OpenBao/Vault whose certificate was issued by a
private CA.

  ssl_ca_file => '/etc/ssl/private-ca.pem',

Without it L<HTTP::Tiny> uses the system's CA bundle (or L<Mozilla::CA>). When
given, the file is used B<instead of> that bundle, and it must be readable —
otherwise every request fails. It has no effect with C<verify_ssl =E<gt> 0>.

=method read_secret($path, version => $n)

The secret C<$path> of every KV method is percent-escaped per segment (the
C</> separators stay), so keys with a space, C<?>, C<#> or C<%> work. Pass the
plain key; an already escaped path would be escaped a second time.

Returns the C<data.data> hashref for a KV v2 secret, or C<undef> if the path
does not exist. By default it reads the latest version; pass
C<version =E<gt> $n> to read a specific earlier version instead, which appends
C<?version=N> to the C<GET .../data/...> request. C<undef> (a soft-deleted or
absent version both answer C<404>) still means "no readable value".

=method read_secret_metadata($path, version => $n)

Returns the C<data.metadata> hashref that KV v2 returns alongside the value on
the same C<GET .../data/...> read — the C<version> number, C<created_time>,
C<destroyed> flag and C<custom_metadata> — or C<undef> on a C<404>. Like
L</read_secret> it reads the latest version by default and takes an optional
C<version =E<gt> $n> to read a specific version's metadata via C<?version=N>.

This is a separate entry point on purpose: L</read_secret> keeps returning the
bare C<data.data> hashref, so callers that only want the values are
unaffected. Note it reads the C<data/> endpoint (the metadata that
accompanies a value read), not the C<metadata/> version-history endpoint.

=method write_secret($path, \%data)

Writes (creates a new version of) a KV v2 secret. Returns the decoded
response.

=method delete_secret($path)

B<Delete ladder level 3 — irreversible, destroys everything.> Removes the key
together with all of its versions and history via
C<DELETE /E<lt>mountE<gt>/metadata/...>. This is the most destructive of the KV
v2 delete operations and there is no undo: despite the plain name it is I<not>
the soft delete a caller might expect. For the reversible level-1 soft delete
of the latest (or of named) versions use L</soft_delete_secret>, reversed by
L</undelete_secret>; to permanently destroy specific versions while keeping the
key and its metadata use L</destroy_secret> (level 2).

=method soft_delete_secret($path, @versions)

B<Delete ladder level 1 — reversible.> Soft-deletes KV v2 versions: they then
read back as C<404>, but the data is retained and can be restored with
L</undelete_secret>. Called with no C<@versions> it soft-deletes the latest
version via C<DELETE /E<lt>mountE<gt>/data/...>; called with one or more version
numbers it soft-deletes exactly those via C<POST /E<lt>mountE<gt>/delete/...>.

=method undelete_secret($path, @versions)

Restores versions previously soft-deleted by L</soft_delete_secret>, via
C<POST /E<lt>mountE<gt>/undelete/...>. At least one version number is required
(it C<croak>s otherwise). This reverses a level-1 soft delete only — it cannot
bring back versions removed by L</destroy_secret> or L</delete_secret>.

=method destroy_secret($path, @versions)

B<Delete ladder level 2 — irreversible.> Permanently destroys the named
versions via C<PUT /E<lt>mountE<gt>/destroy/...>: their contents are gone for
good and cannot be undeleted. The key itself and its metadata survive, so this
is narrower than L</delete_secret> (level 3) but just as final for the versions
it names. At least one version number is required (it C<croak>s otherwise).

=method list_secrets($path)

Returns an arrayref of keys at the given KV v2 metadata path. Empty arrayref
if the path is missing.

=method secret_exists($path)

True if the given path exists, false if it answers C<404>. Does not fetch the
secret data. A C<403> (permission denied) or any other non-2xx C<croak>s, so a
path the token may not see is not reported as absent.

=method login_k8s(role => $role, jwt => $jwt)

Performs a Kubernetes ServiceAccount login. Posts to
C<v1/auth/E<lt>k8s_auth_mountE<gt>/login>, i.e. C<v1/auth/kubernetes/login> by
default; see L</k8s_auth_mount> to reach a method mounted elsewhere. C<role>
is required. C<jwt> defaults to the in-pod ServiceAccount token at
C</var/run/secrets/kubernetes.io/serviceaccount/token>. On success the
returned C<client_token> is stored in L</token> and the full C<auth> hashref
is returned. A C<404> (the auth method is not mounted at
L</k8s_auth_mount>) C<croak>s and leaves L</token> untouched.

=method health

Returns the decoded C</v1/sys/health> response as a hashref for B<every>
reachable server, whatever its seal, standby or init state. The request is made
with C<standbyok=true&perfstandbyok=true&sealedcode=200&uninitcode=200>, so
OpenBao/Vault answers C<200> — and therefore a body — for the states that
otherwise carry their answer only in a non-2xx status code: standby (C<429>),
sealed (C<503>) and uninitialised (C<501>). Read the state out of the returned
fields: C<initialized>, C<sealed>, C<standby>, C<version>,
C<replication_performance_mode> and C<replication_dr_mode> are what OpenBao
delivers, together with C<server_time_utc> and — on an unsealed server —
C<cluster_name> and C<cluster_id>.

C<performance_standby> is a Vault field: it reports the performance-standby
state, which only Vault Enterprise has. OpenBao has no such state and does not
deliver the field at all.

C<standbyok> and C<perfstandbyok> come from the Vault API. OpenBao honours
C<standbyok> the way Vault does, so a standby server answers C<200> there too;
C<perfstandbyok>, Vault's parameter for the performance-standby state, is
unknown to OpenBao and ignored without complaint (checked against OpenBao
2.7.1). The flattening therefore rests on C<standbyok>, C<sealedcode> and
C<uninitcode>.

Because of this, a sealed, uninitialised or standby server yields an
inspectable hashref rather than C<undef>. C<undef> means only that the server
gave no usable answer — a network-level failure, a C<404>, or another non-2xx
status returned in spite of the flattening parameters. C<health> never
C<croak>s.

=method init(secret_shares => $n, secret_threshold => $n)

Initialises an uninitialised server. Both arguments default to C<1>. Use
this for dev/test only.

=method unseal($key)

Submits a single unseal key share.

=method enable_engine($path, $type)

Mounts a secrets engine at C<$path> with the given C<$type> (e.g.
C<kv-v2>).

=method enable_auth($path, $type, %opts)

Enables an auth method of the given C<$type> at C<$path> via
C<POST v1/sys/auth/E<lt>pathE<gt>>. C<%opts> (C<description>, C<config>, ...)
are sent along.

=method write_policy($name, $hcl)

Creates or replaces the ACL policy C<$name> with the policy text C<$hcl> via
C<PUT v1/sys/policies/acl/E<lt>nameE<gt>>. Both arguments are required.

=method read_policy($name)

Returns the text of the ACL policy C<$name>, or C<undef> if there is none.

=method delete_policy($name)

Deletes the ACL policy C<$name>.

=method enable_approle(%opts)

Enables the AppRole auth method at L</approle_auth_mount>. Shorthand for
L</enable_auth> with type C<approle>.

=method ensure_approle_role($name, %opts)

Creates or updates the AppRole role C<$name> with C<%opts> (e.g.
C<token_policies>, C<token_ttl>, C<secret_id_ttl>).

=method approle_role_id($name)

Returns the C<role_id> of the AppRole role C<$name>, or C<undef> if the role
does not exist.

=method approle_secret_id($name, %opts)

Issues a new C<secret_id> for the AppRole role C<$name> and returns it.
C<%opts> (e.g. C<metadata>, C<ttl>) are sent along. Every call issues a fresh
secret id; store it, it cannot be read back.

=method login_approle(role_id => $id, secret_id => $secret)

Performs an AppRole login against L</approle_auth_mount>. Both arguments are
required. On success the returned C<client_token> is stored in L</token> and
the full C<auth> hashref is returned.

=method ensure_token_role($name, %opts)

Creates or updates the token role C<$name> with C<%opts> (e.g.
C<allowed_policies>, C<period>).

=method configure_database($name, %opts)

Configures the connection C<$name> of the database secrets engine at
L</database_mount> with C<%opts> (C<plugin_name>, C<connection_url>,
C<allowed_roles>, C<username>, C<password>, ...). The engine itself is mounted
with L</enable_engine>.

=method database_role($name, %opts)

Creates or updates the database role C<$name> with C<%opts> (C<db_name>,
C<creation_statements>, C<default_ttl>, C<max_ttl>, ...). Credentials for the
role are then issued by L</database_credentials>.

=method database_credentials($name)

Issues a fresh, short-lived credential pair for the database role C<$name>.
Returns a hashref with C<username> and C<password> plus the lease it lives
under — C<lease_id>, C<lease_duration> and C<renewable> — or C<undef> if the
role does not exist. Extend the lease with L</renew_lease>, end it early with
L</revoke_lease>.

=method rotate_root($name)

Rotates the root credential of the database connection C<$name>. Afterwards
only the server knows the password: the one passed to
L</configure_database> no longer works.

=method renew_lease($lease_id, %opts)

Renews the lease C<$lease_id>; C<%opts> may carry C<increment> (seconds).

=method revoke_lease($lease_id)

Revokes the lease C<$lease_id>; the credentials issued under it stop working.

=cut
