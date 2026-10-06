#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use WWW::OpenBao;

# The client carries tokens, unseal keys and secrets, so whether the server
# certificate is verified must not hinge on what HTTP::Tiny happens to default
# to: before 0.083 that default was "off", and
# PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT=1 switches it off on newer versions
# too. Setting the variable here puts every HTTP::Tiny version into the
# "insecure unless told otherwise" state, so these assertions mean the same
# everywhere.
#
# Nothing below opens a connection — only the built, unused HTTP::Tiny object
# is inspected.
local $ENV{PERL_HTTP_TINY_SSL_INSECURE_BY_DEFAULT} = 1;

my $new_bao = sub { WWW::OpenBao->new(endpoint => 'https://bao.test:8200', @_) };

#### Default: verification is on, whatever HTTP::Tiny would have chosen
{
  my $bao = $new_bao->();
  ok $bao->_http->verify_SSL, 'the built HTTP::Tiny verifies certificates by default';
  ok $bao->verify_ssl,        'verify_ssl defaults to true';
  ok !exists $bao->_http->SSL_options->{SSL_ca_file},
     'no CA file is forced on the client unless one is given';
}

#### Switching it off takes an explicit false value
{
  my $bao = $new_bao->(verify_ssl => 0);
  ok !$bao->_http->verify_SSL, 'verify_ssl => 0 turns verification off';
}

#### An undefined value (say, a missing config key) must not switch it off
{
  my $bao = $new_bao->(verify_ssl => undef);
  ok $bao->_http->verify_SSL, 'verify_ssl => undef keeps verification on';
}

#### A private CA is handed through, with verification still on
{
  my $bao = $new_bao->(ssl_ca_file => '/etc/ssl/lab-ca.pem');
  is $bao->_http->SSL_options->{SSL_ca_file}, '/etc/ssl/lab-ca.pem',
     'ssl_ca_file reaches HTTP::Tiny as SSL_ca_file';
  ok $bao->_http->verify_SSL, 'verification stays on when a CA file is given';
}

done_testing;
