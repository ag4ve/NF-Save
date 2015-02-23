#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $tests = [
  [[$ipt->_each_kv([qw/a b c d/])], 1, "Add array to iterator"],
  [[$ipt->_each_kv('keys')], [qw/a c/], "All keys"],
  [[$ipt->_each_kv('values')], [qw/b d/], "All values"],
  [[$ipt->_each_kv('keys b')], [qw/a/], "Keys for value search"],
  [[$ipt->_each_kv('values c')], [qw/d/], "Values for key search"],
  [[$ipt->_each_kv()], [qw/a b/], "Retured first two in list"],
  [[$ipt->_each_kv([qw/e f g/])], 0, "Add invalid array"],
  [[$ipt->_each_kv()], [qw/c d/], "Returned last two in list"],
  [[$ipt->_each_kv()], [], "Nothing left in list"],
  [[$ipt->_each_kv([qw/a b c d/], 'foo')], 1, "Add array to named iterator"],
  [[$ipt->_each_kv('keys', 'foo')], [qw/a c/], "All named keys"],
  [[$ipt->_each_kv(undef, 'foo')], [qw/a b/], "Retured first two in named list"],
  [[$ipt->_each_kv(undef, 'foo')], [qw/c d/], "Returned last two in named list"],
  [[$ipt->_each_kv(undef, 'foo')], [], "Nothing left in named list"],
];

test($tests);
