#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'uids' => {'testuser' => 359}});

my $struct = {
  'in' => "eth0",
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
  [
    $ipt->assemble($struct),
    [
      ['-d 192.168.15.1/32'],
      ['-i eth0'],
      ['-p udp -m udp --sport 1024:65535 --dport 53'],
      ['-m comment --comment "nameserver"'],
      ['-j ACCEPT'],
    ],
    "Assemble rule",
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

