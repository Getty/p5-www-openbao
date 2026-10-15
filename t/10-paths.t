#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use WWW::OpenBao;

my $bao = WWW::OpenBao->new(
  endpoint => 'http://vault:8200',
  token    => 'test-token',
);

ok  $bao,                                 'constructor';
is  $bao->endpoint, 'http://vault:8200',  'endpoint';
is  $bao->token,    'test-token',         'token';
is  $bao->kv_mount, 'secret',             'default kv_mount';

is $bao->_kv_path('foo/bar'),
   'v1/secret/data/foo/bar',              'kv data path';
is $bao->_kv_metadata_path('foo/bar'),
   'v1/secret/metadata/foo/bar',          'kv metadata path';
is $bao->_kv_delete_path('foo/bar'),
   'v1/secret/delete/foo/bar',            'kv soft-delete path';
is $bao->_kv_undelete_path('foo/bar'),
   'v1/secret/undelete/foo/bar',          'kv undelete path';
is $bao->_kv_destroy_path('foo/bar'),
   'v1/secret/destroy/foo/bar',           'kv destroy path';

$bao->token('new-token');
is $bao->token, 'new-token',              'token is writable (login flows)';

my $bao2 = WWW::OpenBao->new(
  endpoint => 'http://vault:8200',
  kv_mount => 'goldmine',
);
is $bao2->_kv_path('a/b'),
   'v1/goldmine/data/a/b',                'custom kv_mount honoured';

# k11: segments are escaped, separators and unreserved characters are not
is $bao->_kv_path('a b/c?d#e%f'),
   'v1/secret/data/a%20b/c%3Fd%23e%25f',  'kv path escapes space ? # %';
is $bao->_kv_metadata_path("k\x{20ac}"),
   'v1/secret/metadata/k%E2%82%AC',          'kv path escapes characters as UTF-8';
is $bao->_kv_path('foo-bar_1.2~x/y'),
   'v1/secret/data/foo-bar_1.2~x/y',      'kv path keeps unreserved characters and /';

done_testing;
