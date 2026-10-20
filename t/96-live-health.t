#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

# Live test against a running OpenBao. Off unless OPENBAO_TEST_URL is set,
# e.g. OPENBAO_TEST_URL=http://127.0.0.1:18200. /v1/sys/health needs no
# token, so OPENBAO_TEST_TOKEN is optional and only for a server that asks
# for one.
#
# The test only reads. It shows what a real OpenBao answers for a server in
# any state: the flattening parameters of health() turn standby, sealed and
# uninitialised into a 200 with a body, and that body carries the OpenBao
# fields - and no performance_standby, which is a Vault field.

BEGIN {
  plan skip_all => 'set OPENBAO_TEST_URL to run the OpenBao live test'
    unless $ENV{OPENBAO_TEST_URL} && length $ENV{OPENBAO_TEST_URL};
}

use WWW::OpenBao;

my $bao = WWW::OpenBao->new(
  endpoint => $ENV{OPENBAO_TEST_URL},
  token    => $ENV{OPENBAO_TEST_TOKEN} // '',
);

my $health;
my $died = !eval { $health = $bao->health; 1 };
my $error = $died ? $@ : undef;

ok !$died, 'health does not croak' or diag $error;

SKIP: {
  skip 'no health hashref to look at', 6
    if $died || !defined $health || ref $health ne 'HASH';

  diag sprintf 'server state: initialized=%s sealed=%s standby=%s version=%s',
    map { defined $health->{$_} ? $health->{$_} : '?' }
    qw( initialized sealed standby version );

  ok exists $health->{initialized}, 'the body carries initialized';
  ok exists $health->{sealed},      'the body carries sealed';
  ok exists $health->{standby},     'the body carries standby';
  ok exists $health->{version},     'the body carries version';
  ok exists $health->{replication_performance_mode},
    'the body carries replication_performance_mode';
  ok !exists $health->{performance_standby},
    'the body carries no performance_standby - that is a Vault field';
}

done_testing;
