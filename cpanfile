requires 'Carp';
requires 'HTTP::Tiny',    '0.080';
requires 'JSON::MaybeXS', '1.004000';
requires 'Moo',           '2.000000';
requires 'namespace::clean';

on test => sub {
  requires 'Test::More', '0.98';
};
