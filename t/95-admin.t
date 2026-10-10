#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS;

use WWW::OpenBao;

# Same offline pattern as t/20-request.t and t/30-login-k8s.t: stub the lazy
# _http attribute so no request leaves the process. The stub answers from a
# queue of canned HTTP::Tiny-shaped responses and records every call, so each
# test asserts the exact method, path and body an admin call sends.
package Test::OpenBao::HTTPStub;

sub new { bless { queue => [], calls => [] }, $_[0] }

sub push_response {
  my ($self, $status, $body) = @_;
  push @{ $self->{queue} }, {
    status  => $status,
    success => ($status >= 200 && $status < 300 ? 1 : 0),
    content => (defined $body ? JSON::MaybeXS::encode_json($body) : ''),
  };
  return $self;
}

sub request {
  my ($self, $method, $url, $opts) = @_;
  push @{ $self->{calls} }, {
    method => $method, url => $url,
    body   => ($opts->{content} ? JSON::MaybeXS::decode_json($opts->{content}) : undef),
    token  => $opts->{headers}{'X-Vault-Token'},
  };
  return shift @{ $self->{queue} } // { status => 204, success => 1, content => '' };
}

sub last_call { $_[0]->{calls}[-1] }

package main;

my $new_bao = sub {
  my (%args) = @_;
  my $stub = Test::OpenBao::HTTPStub->new;
  my $bao  = WWW::OpenBao->new(
    endpoint => 'https://bao.example', token => 'root-token', _http => $stub, %args,
  );
  return ($bao, $stub);
};

my $sent = sub {
  my ($stub, $method, $path, $body, $name) = @_;
  my $call = $stub->last_call;
  is($call->{method}, $method, "$name: method");
  is($call->{url}, "https://bao.example/$path", "$name: path");
  is_deeply($call->{body}, $body, "$name: body");
  is($call->{token}, 'root-token', "$name: sent with the token");
};

subtest 'policies' => sub {
  my ($bao, $stub) = $new_bao->();
  $bao->write_policy('platform', 'path "secret/data/platform/*" { capabilities = ["read"] }');
  $sent->($stub, 'PUT', 'v1/sys/policies/acl/platform',
    { policy => 'path "secret/data/platform/*" { capabilities = ["read"] }' }, 'write_policy');

  eval { $bao->write_policy('platform', '') };
  like($@, qr/policy text/, 'write_policy refuses an empty policy');
  eval { $bao->write_policy(undef, 'x') };
  like($@, qr/policy name/, 'write_policy refuses a missing name');

  $stub->push_response(200, { data => { name => 'platform', policy => 'path "x" {}' } });
  is($bao->read_policy('platform'), 'path "x" {}', 'read_policy returns the policy text');
  $sent->($stub, 'GET', 'v1/sys/policies/acl/platform', undef, 'read_policy');

  $stub->push_response(404);
  is($bao->read_policy('nope'), undef, 'read_policy is undef for a missing policy');

  $bao->delete_policy('platform');
  $sent->($stub, 'DELETE', 'v1/sys/policies/acl/platform', undef, 'delete_policy');
};

subtest 'auth methods and AppRole' => sub {
  my ($bao, $stub) = $new_bao->();
  $bao->enable_auth('userpass', 'userpass', description => 'people');
  $sent->($stub, 'POST', 'v1/sys/auth/userpass',
    { type => 'userpass', description => 'people' }, 'enable_auth');

  $bao->enable_auth('x', 'approle', type => 'not-this');
  is($stub->last_call->{body}{type}, 'approle', 'enable_auth: the named type wins over %opts');

  $bao->enable_approle;
  $sent->($stub, 'POST', 'v1/sys/auth/approle', { type => 'approle' }, 'enable_approle');

  $bao->ensure_approle_role('platform', token_policies => ['platform'], token_ttl => '1h');
  $sent->($stub, 'POST', 'v1/auth/approle/role/platform',
    { token_policies => ['platform'], token_ttl => '1h' }, 'ensure_approle_role');

  $stub->push_response(200, { data => { role_id => 'role-123' } });
  is($bao->approle_role_id('platform'), 'role-123', 'approle_role_id returns the role id');
  $sent->($stub, 'GET', 'v1/auth/approle/role/platform/role-id', undef, 'approle_role_id');

  $stub->push_response(404);
  is($bao->approle_role_id('nope'), undef, 'approle_role_id is undef for a missing role');

  $stub->push_response(200, { data => { secret_id => 'secret-456', secret_id_accessor => 'acc' } });
  is($bao->approle_secret_id('platform', ttl => '10m'), 'secret-456',
    'approle_secret_id returns the secret id');
  $sent->($stub, 'POST', 'v1/auth/approle/role/platform/secret-id', { ttl => '10m' },
    'approle_secret_id');
};

subtest 'login_approle' => sub {
  my ($bao, $stub) = $new_bao->();
  $stub->push_response(200, { auth => { client_token => 'service-token', policies => ['platform'] } });
  my $auth = $bao->login_approle(role_id => 'role-123', secret_id => 'secret-456');
  is($stub->last_call->{url}, 'https://bao.example/v1/auth/approle/login', 'posts to the login path');
  is_deeply($stub->last_call->{body}, { role_id => 'role-123', secret_id => 'secret-456' },
    'sends role id and secret id');
  is($bao->token, 'service-token', 'the client token is stored');
  is_deeply($auth->{policies}, ['platform'], 'the auth hashref is returned');

  eval { $bao->login_approle(secret_id => 'x') };
  like($@, qr/role_id/, 'role_id is required');
  eval { $bao->login_approle(role_id => 'x') };
  like($@, qr/secret_id/, 'secret_id is required');

  my ($bao2, $stub2) = $new_bao->();
  $stub2->push_response(404);
  eval { $bao2->login_approle(role_id => 'a', secret_id => 'b') };
  like($@, qr/not mounted at approle/, 'a 404 on login croaks instead of wiping the token');
  is($bao2->token, 'root-token', '... and the token is untouched');

  my ($bao3, $stub3) = $new_bao->();
  $stub3->push_response(400, { errors => ['invalid role or secret ID'] });
  eval { $bao3->login_approle(role_id => 'a', secret_id => 'wrong') };
  like($@, qr/400/, 'a refused login croaks');
  is($bao3->token, 'root-token', '... and the token is untouched');
};

subtest 'approle_auth_mount' => sub {
  my ($bao, $stub) = $new_bao->(approle_auth_mount => 'services');
  $bao->enable_approle;
  is($stub->last_call->{url}, 'https://bao.example/v1/sys/auth/services', 'enable_approle follows the mount');
  $bao->ensure_approle_role('platform');
  is($stub->last_call->{url}, 'https://bao.example/v1/auth/services/role/platform',
    'ensure_approle_role follows the mount');
  $stub->push_response(200, { auth => { client_token => 't' } });
  $bao->login_approle(role_id => 'a', secret_id => 'b');
  is($stub->last_call->{url}, 'https://bao.example/v1/auth/services/login', 'login_approle follows the mount');
};

subtest 'token roles' => sub {
  my ($bao, $stub) = $new_bao->();
  $bao->ensure_token_role('deployer', allowed_policies => ['deploy'], period => '24h');
  $sent->($stub, 'POST', 'v1/auth/token/roles/deployer',
    { allowed_policies => ['deploy'], period => '24h' }, 'ensure_token_role');
};

subtest 'database engine' => sub {
  my ($bao, $stub) = $new_bao->();
  $bao->configure_database('pg',
    plugin_name    => 'postgresql-database-plugin',
    connection_url => 'postgresql://{{username}}:{{password}}@pg:5432/postgres',
    allowed_roles  => ['platform'],
  );
  $sent->($stub, 'POST', 'v1/database/config/pg', {
    plugin_name    => 'postgresql-database-plugin',
    connection_url => 'postgresql://{{username}}:{{password}}@pg:5432/postgres',
    allowed_roles  => ['platform'],
  }, 'configure_database');

  $bao->database_role('platform', db_name => 'pg', default_ttl => '1h');
  $sent->($stub, 'POST', 'v1/database/roles/platform',
    { db_name => 'pg', default_ttl => '1h' }, 'database_role');

  $stub->push_response(200, {
    lease_id => 'database/creds/platform/abc', lease_duration => 3600, renewable => JSON::MaybeXS::true,
    data     => { username => 'v-platform-x', password => 'pw' },
  });
  my $creds = $bao->database_credentials('platform');
  $sent->($stub, 'GET', 'v1/database/creds/platform', undef, 'database_credentials');
  is($creds->{username}, 'v-platform-x', 'credentials carry the username');
  is($creds->{password}, 'pw', '... the password');
  is($creds->{lease_id}, 'database/creds/platform/abc', '... the lease id');
  is($creds->{lease_duration}, 3600, '... and the lease duration');
  ok($creds->{renewable}, '... and whether the lease is renewable');

  $stub->push_response(404);
  is($bao->database_credentials('nope'), undef, 'database_credentials is undef for a missing role');

  $bao->rotate_root('pg');
  $sent->($stub, 'POST', 'v1/database/rotate-root/pg', undef, 'rotate_root');

  my ($bao2, $stub2) = $new_bao->(database_mount => 'db-live');
  $bao2->configure_database('pg', plugin_name => 'p');
  is($stub2->last_call->{url}, 'https://bao.example/v1/db-live/config/pg', 'database_mount is followed');
  $bao2->rotate_root('pg');
  is($stub2->last_call->{url}, 'https://bao.example/v1/db-live/rotate-root/pg', '... by rotate_root too');
};

subtest 'leases' => sub {
  my ($bao, $stub) = $new_bao->();
  $bao->renew_lease('database/creds/platform/abc', increment => 600);
  $sent->($stub, 'PUT', 'v1/sys/leases/renew',
    { lease_id => 'database/creds/platform/abc', increment => 600 }, 'renew_lease');
  $bao->renew_lease('real', lease_id => 'smuggled');
  is($stub->last_call->{body}{lease_id}, 'real', 'renew_lease: the named lease wins over %opts');

  $bao->revoke_lease('database/creds/platform/abc');
  $sent->($stub, 'PUT', 'v1/sys/leases/revoke',
    { lease_id => 'database/creds/platform/abc' }, 'revoke_lease');

  eval { $bao->renew_lease('') };
  like($@, qr/lease id/, 'renew_lease requires a lease id');
  eval { $bao->revoke_lease(undef) };
  like($@, qr/lease id/, 'revoke_lease requires a lease id');
};

done_testing;
