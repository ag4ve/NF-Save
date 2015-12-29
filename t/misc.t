#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $oIPT = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $paTests = 
[
  [
    [$oIPT->_sortpre([qw/x a d/], [qw/d a z x/])],
    [qw/d a x/],
    "Sort list in with a rule."
  ], 
  [
    [$oIPT->get_uids('t/passwd')],
    [{'testuser' => 359}],
    "Data from passwd file."
  ],
];


test($paTests);

