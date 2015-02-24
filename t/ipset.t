#
#===============================================================================
#
#         FILE: ipset.t
#
#  DESCRIPTION: 
#
#        FILES: ---
#         BUGS: ---
#        NOTES: ---
#       AUTHOR: YOUR NAME (), 
# ORGANIZATION: 
#      VERSION: 1.0
#      CREATED: 02/11/2015 04:23:55 PM
#     REVISION: ---
#===============================================================================

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $tests = [
  [
    [$ipt->add_list('test', [qw/1.2.3.4 5.6.7.8/], {'hashsize' => 2048})], 
    [1], 
    "Save IPSET (add_list)"
  ],
  [
    [$ipt->get_ipset()],
    [
      'create test hash:net family inet hashsize 2048 maxelen 65536',
      'add test 1.2.3.4/32',
      'add test 5.6.7.8/32',
    ],
    "IPSET return data"
  ],
  [$ipt->is_ipset('test'), 1, "The queried IPSET exists"],
  [$ipt->is_ipset('foo'), 0, "The queried IPSET does not exist"],
  [$ipt->get_ipset_data('test'), {'list' => [qw(1.2.3.4/32 5.6.7.8/32)], 'hashsize' => 2048}, "IPSET data"],
  [
    $ipt->_list_set({
      'name' => "test",
      'direction' => [qw/src dst/],
      'useipset' => 1,
    }),
    ['-m set --match-set test src,dst'],
    "Source and destination list",
  ],
  [
    $ipt->_list_set({
      'name' => "test",
      'direction' => 'src',
    }),
    [
      '-s 1.2.3.4/32',
      '-s 5.6.7.8/32',
    ],
    "Source list (no IPSET)",
  ],
  [[$ipt->_list_set({'name' => "foo"})], [], "Non-existent list"],
];


test($tests);

