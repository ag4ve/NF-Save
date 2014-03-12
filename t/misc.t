#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'testuser' => 359});

my $struct = {
  'proto' => "UDP",
  'module' => {
    'name' => "UDP",
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
  [$ipt->_list_set({'name' => "foo"}), undef, "Non-existent list"],
  [
    $ipt->assemble($struct),
    ['-A OUTPUT -p UDP --sport 1024:65535 -d 192.168.15.1 --dport 53 -j ACCEPT -m comment --comment "nameserver"'],
    "Assemble rule",
  ],
];



# $t->save();
# [-A OUTPUT -p UDP --sport 1024:65535 -d 192.168.15.1 --dport 53 -j ACCEPT -m comment --comment "nameserver"]


test($tests);

