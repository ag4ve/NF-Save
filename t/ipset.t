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

my $oIPT = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $paTests = 
[
  [
    [$oIPT->add_list('test', [qw/1.2.3.4 5.6.7.8/], {'hashsize' => 2048})], 
    [1], 
    "Save IPSET (add_list)"
  ],
  [
    [$oIPT->get_ipset()],
    [
      'create test hash:net family inet hashsize 2048 maxelen 65536',
      'add test 1.2.3.4/32',
      'add test 5.6.7.8/32',
    ],
    "IPSET return data"
  ],
  [
    $oIPT->is_ipset('test'), 
    1, 
    "The queried IPSET exists"
  ],
  [
    $oIPT->is_ipset('foo'), 
    0, 
    "The queried IPSET does not exist"
  ],
  [
    $oIPT->get_ipset_data('test'), 
    {
      'list' => 
      [
        "1.2.3.4/32",
        "5.6.7.8/32"
      ], 
      'hashsize' => 2048
    }, 
    "IPSET data"
  ],
  [
    $oIPT->_list_set(
      {
        'name' => "test",
        'direction' => [qw/src dst/],
        'useipset' => 1,
      }
    ),
    ['-m set --match-set test src,dst'],
    "Source and destination list",
  ],
  [
    $oIPT->_list_set(
      {
        'name' => "test",
        'direction' => 'src',
      }
    ),
    [
      '-s 1.2.3.4/32',
      '-s 5.6.7.8/32',
    ],
    "Source list (no IPSET)",
  ],
  [
    [$oIPT->_list_set({'name' => "foo"})], 
    [], 
    "Non-existent list"
  ],
];


test($paTests);

