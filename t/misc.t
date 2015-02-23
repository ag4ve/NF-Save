#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $tests = [
  [
    [$ipt->_sortpre(
      [qw/x a d/],
      [qw/d a z x/]
    )],
    [qw/d a x/],
    "Sort list in with a rule."
  ],
];


test($tests);

