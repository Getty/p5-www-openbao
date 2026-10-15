#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use JSON::MaybeXS;

use WWW::OpenBao;

# Minimal stub for the lazy _http attribute: request() returns a canned
# HTTP::Tiny-shaped response ({status, success, content}) and records what
# it was called with, so a test can also assert the seam actually reached
# the stub rather than short-circuiting somewhere else.
package Test::OpenBao::HTTPStub;

sub new {
  my ($class, $response) = @_;
  return bless { response => $response, calls => [] }, $class;
}

sub request {
  my ($self, $method, $url, $opts) = @_;
  push @{ $self->{calls} }, { method => $method, url => $url, opts => $opts };
  return $self->{response};
}

sub call_count { scalar @{ $_[0]->{calls} } }

package main;

my $new_bao = sub {
  my ($response) = @_;
  my $stub = Test::OpenBao::HTTPStub->new($response);
  my $bao  = WWW::OpenBao->new(
    endpoint => 'http://test',
    token    => 't',
    _http    => $stub,
  );
  return ($bao, $stub);
};

#### Case 1: 2xx with a JSON body is decode_json-ed into a hashref
{
  my $payload = { data => { data => { user => 'app' } }, extra => 'x' };
  my ($bao, $stub) = $new_bao->({
    status  => 200,
    success => 1,
    content => encode_json($payload),
  });

  my $result = $bao->_request('GET', 'v1/secret/data/foo/bar');
  is_deeply $result, $payload, '2xx JSON body decodes to the matching hashref';
  is $stub->call_count, 1,     'the _http stub was actually invoked';
}

#### Case 2: successful response with empty content yields {} (204 case)
{
  my ($bao, $stub) = $new_bao->({
    status  => 204,
    success => 1,
    content => '',
  });

  my $result = $bao->_request('POST', 'v1/secret/data/foo/bar');
  is_deeply $result, {}, '204 / empty content on success yields an empty hashref';
}

#### Case 3: 404 always yields undef, regardless of the success flag
{
  my ($bao, $stub) = $new_bao->({
    status  => 404,
    success => 0,
    content => '{"errors":["no value found"]}',
  });
  is $bao->_request('GET', 'v1/secret/data/missing'), undef,
     '404 with success=0 returns undef';
}
{
  my ($bao, $stub) = $new_bao->({
    status  => 404,
    success => 1,
    content => '',
  });
  is $bao->_request('GET', 'v1/secret/data/missing'), undef,
     '404 with success=1 still returns undef (status check wins over success)';
}

#### Case 4: any other non-2xx croaks, naming method and path
{
  my ($bao, $stub) = $new_bao->({
    status  => 500,
    success => 0,
    content => '{"errors":["internal error"]}',
  });

  my $result = eval { $bao->_request('GET', 'v1/secret/data/boom') };
  my $err    = $@;

  ok !defined $result, 'nothing is returned when _request croaks';
  ok $err,             'non-2xx response croaks';
  like $err, qr/OpenBao\s+GET\s+v1\/secret\/data\/boom/,
     'croak message names both the HTTP method and the path';
}

#### Case 5 (k15): a 404 on a write croaks, reads and secret_exists stay soft
{
  my %writes = (
    write_secret       => sub { $_[0]->write_secret('app/db', { p => 1 }) },
    delete_secret      => sub { $_[0]->delete_secret('app/db') },
    soft_delete_secret => sub { $_[0]->soft_delete_secret('app/db') },
    soft_delete_vers   => sub { $_[0]->soft_delete_secret('app/db', 1) },
    undelete_secret    => sub { $_[0]->undelete_secret('app/db', 1) },
    destroy_secret     => sub { $_[0]->destroy_secret('app/db', 1) },
    init               => sub { $_[0]->init },
    unseal             => sub { $_[0]->unseal('key') },
    enable_engine      => sub { $_[0]->enable_engine('kv', 'kv-v2') },
    enable_auth        => sub { $_[0]->enable_auth('x', 'approle') },
    write_policy       => sub { $_[0]->write_policy('p', 'path "x" {}') },
    delete_policy      => sub { $_[0]->delete_policy('p') },
    ensure_approle     => sub { $_[0]->ensure_approle_role('r') },
    ensure_token_role  => sub { $_[0]->ensure_token_role('r') },
    configure_database => sub { $_[0]->configure_database('pg') },
    database_role      => sub { $_[0]->database_role('r') },
    rotate_root        => sub { $_[0]->rotate_root('pg') },
    renew_lease        => sub { $_[0]->renew_lease('l/1') },
    revoke_lease       => sub { $_[0]->revoke_lease('l/1') },
  );
  for my $name (sort keys %writes) {
    my ($bao) = $new_bao->({ status => 404, success => 0, content => '{"errors":[]}' });
    my $r = eval { $writes{$name}->($bao) };
    like $@, qr/^OpenBao \w+ \S+: 404 /, "$name croaks on a 404";
  }

  my ($bao) = $new_bao->({ status => 404, success => 0, content => '' });
  is $bao->read_secret('app/db'), undef, 'read_secret keeps the soft miss';
  is_deeply $bao->list_secrets('app/'), [], 'list_secrets keeps the soft miss';
  ok !$bao->secret_exists('app/db'), 'secret_exists keeps the soft miss';
}

#### Case 6 (k12): a trailing slash on endpoint does not double the slash
{
  my $stub = Test::OpenBao::HTTPStub->new({ status => 200, success => 1, content => '{}' });
  my $bao  = WWW::OpenBao->new(endpoint => 'http://test/', token => 't', _http => $stub);
  $bao->_request('GET', 'v1/sys/health');
  is $stub->{calls}[0]{url}, 'http://test/v1/sys/health', 'no // after the endpoint';
  is $bao->endpoint, 'http://test/', 'the endpoint attribute itself is untouched';
}

done_testing;
