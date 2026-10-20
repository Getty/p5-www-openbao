#!/usr/bin/env perl

use strict;
use warnings;
use File::Spec;
use FindBin;
use Test::More;

my $cpanfile = File::Spec->catfile( $FindBin::Bin, File::Spec->updir, 'cpanfile' );

plan skip_all => 'cpanfile is not part of the distribution' unless -f $cpanfile;

open my $fh, '<', $cpanfile or die "cannot read $cpanfile: $!";
my %runtime;
my %test;
my @runtime_order;
my $in_test = 0;
while ( my $line = <$fh> ) {
    if ( $line =~ /^\s*on\s+test\s*=>\s*sub\s*\{/ ) {
        $in_test = 1;
        next;
    }
    if ( $in_test && $line =~ /^\s*\};/ ) {
        $in_test = 0;
        next;
    }
    next unless $line =~ /^\s*requires\s+'([^']+)'(?:\s*,\s*'([^']+)')?/;
    my ( $module, $version ) = ( $1, $2 );
    if ($in_test) { $test{$module} = $version }
    else {
        $runtime{$module} = $version;
        push @runtime_order, $module;
    }
}
close $fh;

# Every library the code loads has to be a declared prerequisite, otherwise a
# fresh install fails when the library is loaded and not when the
# distribution is built. The runtime list is the chain lib/ loads; core
# modules (Carp) need no declaration.
#
# Where the module name and the distribution name differ, the distribution
# counts, so the cpanfile may spell the prerequisite either way - the
# distribution name stands in parentheses.
my @runtime = (
    [ 'HTTP::Tiny',       'HTTP-Tiny' ],
    [ 'JSON::MaybeXS',    'JSON-MaybeXS' ],
    [ 'Moo',              'Moo' ],
    [ 'namespace::clean', 'namespace-clean' ],
);

my @test = (
    [ 'Test::More', 'Test-More' ],
);

sub declared {
    my ( $phase, $prereq ) = @_;
    for my $name (@$prereq) {
        return 1 if exists $phase->{$name};
    }
    return 0;
}

# A runtime prerequisite has to stand in the runtime phase: an entry in the
# test phase alone is not installed when the distribution is applied.
for my $prereq (@runtime) {
    my ($module) = @$prereq;
    ok( declared( \%runtime, $prereq ), "$module is a declared runtime prerequisite" );
}

# A test prerequisite is declared in the test phase or in the runtime phase -
# the runtime phase is installed either way.
for my $prereq (@test) {
    my ($module) = @$prereq;
    ok( declared( \%runtime, $prereq ) || declared( \%test, $prereq ),
        "$module is a declared test prerequisite" );
}

# House form of the cpanfile: the runtime requirements stand alphabetically
# and no requirement carries the empty pin '0' - a version of '0' states
# nothing.
is_deeply( \@runtime_order, [ sort @runtime_order ],
    'the runtime requirements stand alphabetically' );

my %all = ( %runtime, %test );
my @empty_pins = sort grep { ( $all{$_} // '' ) eq '0' } keys %all;
is_deeply( \@empty_pins, [], 'no requirement carries the empty pin 0' );

done_testing;
