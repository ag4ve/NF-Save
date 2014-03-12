#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'testuser' => 359});

my $tests = [
  [[$ipt->_each_kv([qw/a b c d/])], 1, "Add array to iterator"],
  [[$ipt->_each_kv()], [qw/a b/], "Retured first two values"],
  [[$ipt->_each_kv([qw/e f g/])], 0, "Add invalid array"],
  [[$ipt->_each_kv()], [qw/c d/], "Returned last two values"],
  [[$ipt->_each_kv()], [], "Nothing left in list"],
];

test($tests);
