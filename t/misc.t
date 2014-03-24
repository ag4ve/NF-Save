#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'uids' => {'testuser' => 359}});

my $struct = {
  'udp' => {
    'sport' => "1024:65535",
    'dport' => "53",
  }, 
  'dst' => "192.168.15.1",
  'comment' => [qw/nameserver/],
  'jump' => "ACCEPT",
};

$ipt->rule('OUTPUT', $struct);

my $tests = [
  [$ipt->get(), {'filter' => {'OUTPUT' => [$struct]}}, "Same structures"],
  [$ipt->ipset('test', [qw/1.2.3.4 5.6.7.8/], {'hashsize' => 2048}), 1, "Save IPSET"],
  [
    $ipt->get_ipset(),
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
  [
    $ipt->assemble($struct),
    [
      ['-d 192.168.15.1/32'],
      ['-p udp -m udp --sport 1024:65535 --dport 53'],
      ['-m comment --comment "nameserver"'],
      ['-j ACCEPT'],
    ],
    "Assemble rule (1)",
  ],
  [
    $ipt->assemble($struct),
    [
      ['-d 192.168.15.1/32'],
      ['-p udp -m udp --sport 1024:65535 --dport 53'],
      ['-m comment --comment "nameserver"'],
      ['-j ACCEPT'],
    ],
    "Assemble rule (2)",
  ],
  [
    $ipt->save_chain('OUTPUT'), 
    ['-A OUTPUT -d 192.168.15.1/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT'],
    "Get full chain rule set.",
  ],
  [
    $ipt->save_table(), 
    ['-A OUTPUT -d 192.168.15.1/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT'],
    "Get full table rule set.",
  ],
];


test($tests);

