package WWW::OpenBao;
# ABSTRACT: HTTP client for OpenBao / HashiCorp Vault API

use Moo;
use HTTP::Tiny;
use JSON::MaybeXS;
use Carp qw(croak);
use namespace::clean;

has endpoint  => (is => 'ro', required => 1);
has token     => (is => 'rw', default => sub { '' });
has kv_mount  => (is => 'ro', default => sub { 'secret' });
has _http     => (is => 'lazy');

sub _build__http { HTTP::Tiny->new(timeout => 10) }

# KV v2 paths
sub _kv_path          { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/data/$p" }
sub _kv_metadata_path { my ($self, $p) = @_; "v1/" . $self->kv_mount . "/metadata/$p" }

# Core HTTP
sub _request {
  my ($self, $method, $path, $body) = @_;
  my $url = $self->endpoint . '/' . $path;
  my %opts = (headers => {
    'X-Vault-Token' => $self->token,
  });
  if ($body) {
    $opts{content} = encode_json($body);
    $opts{headers}{'Content-Type'} = 'application/json';
  }
  my $resp = $self->_http->request($method, $url, \%opts);
  return undef if $resp->{status} == 404;
  croak "OpenBao $method $path: $resp->{status} $resp->{content}"
    unless $resp->{success};
  return $resp->{content} ? decode_json($resp->{content}) : {};
}

# KV v2: read secret data
sub read_secret {
  my ($self, $path) = @_;
  my $resp = $self->_request('GET', $self->_kv_path($path));
  return undef unless $resp;
  return $resp->{data}{data};
}

# KV v2: write secret data
sub write_secret {
  my ($self, $path, $data) = @_;
  return $self->_request('POST', $self->_kv_path($path), { data => $data });
}

# KV v2: delete secret (all versions + metadata)
sub delete_secret {
  my ($self, $path) = @_;
  return $self->_request('DELETE', $self->_kv_metadata_path($path));
}

# KV v2: list secrets at path
sub list_secrets {
  my ($self, $path) = @_;
  my $resp = $self->_request('LIST', $self->_kv_metadata_path($path));
  return [] unless $resp;
  return $resp->{data}{keys} // [];
}

# KV v2: check if secret exists without fetching data
sub secret_exists {
  my ($self, $path) = @_;
  my $resp = eval { $self->_request('GET', $self->_kv_metadata_path($path)) };
  return defined $resp;
}

# Auth: Kubernetes ServiceAccount login
sub login_k8s {
  my ($self, %args) = @_;
  my $role = $args{role} // croak "login_k8s requires 'role'";
  my $jwt  = $args{jwt}  // _read_sa_token();
  my $resp = $self->_request('POST', 'v1/auth/kubernetes/login', {
    role => $role, jwt => $jwt,
  });
  $self->token($resp->{auth}{client_token});
  return $resp->{auth};
}

sub _read_sa_token {
  my $path = '/var/run/secrets/kubernetes.io/serviceaccount/token';
  open my $fh, '<', $path or croak "Cannot read SA token: $!";
  local $/;
  return <$fh>;
}

# Sys: health check
sub health {
  my ($self) = @_;
  return eval { $self->_request('GET', 'v1/sys/health') };
}

# Sys: initialize vault (first time)
sub init {
  my ($self, %args) = @_;
  my $shares    = $args{secret_shares}    // 1;
  my $threshold = $args{secret_threshold} // 1;
  return $self->_request('POST', 'v1/sys/init', {
    secret_shares => $shares, secret_threshold => $threshold,
  });
}

# Sys: unseal
sub unseal {
  my ($self, $key) = @_;
  return $self->_request('POST', 'v1/sys/unseal', { key => $key });
}

# Sys: enable secrets engine
sub enable_engine {
  my ($self, $path, $type) = @_;
  return $self->_request('POST', "v1/sys/mounts/$path", { type => $type });
}

1;
