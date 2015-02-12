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

my $assembled = [
  ['-d 192.168.15.1/32'],
  ['-i eth0'],
  ['-p udp -m udp --sport 1024:65535 --dport 53'],
  ['-m comment --comment "nameserver"'],
  ['-j ACCEPT'],
];

$ipt->rule('OUTPUT', $struct);

my $tests = [
  [$ipt->is_table('filter'), [1], "Table filter exists."],
  [$ipt->is_table('foobar'), [0], "Table foobar does not exist."],
  [$ipt->is_chain('OUTPUT'), [1], "Chain OUTPUT exists."],
  [$ipt->is_chain('OUTPUT', 'filter'), [1], "Chain OUTPUT in table filter exists."],
  [$ipt->is_chain('OUTPUT', 'foobar'), [0], "Chain OUTPUT in table foobar does not exist."],
  [$ipt->is_chain('foobar', 'filter'), [0], "Chain foobar in table filter exists."],
  [$ipt->get_rules('OUTPUT'), $struct, "Get stored rules from OUTPUT."],
  [$ipt->get_rules('OUTPUT', 'filter'), $struct, "Get stored rules from OUTPUT chain in filter table."],
  [$ipt->get_rules('INPUT', 'filter'), undef, "Get stored rules from INPUT chain in filter table (undef)."],
  [$ipt->get_policy('INPUT'), 'DROP', "Policy for INPUT in (unspecified) filter table."],
  [$ipt->get_policy('OUTPUT', 'filter'), 'DROP', "Policy for OUTPUT in filter table."],
  [$ipt->get_policy('OUTPUT', 'mangle'), 'ACCEPT', "Policy for OUTPUT in mangle table."],
  [$ipt->get_policy('foobar', 'mangle'), undef, undef, "Policy for foobar in mangle table (undef)."],
  [$ipt->get(), {'filter' => {'OUTPUT' => [$struct]}}, "Same structures."],
  [$ipt->assemble($struct), $assembled, "Assemble rule."],
  [
    $ipt->save_chain('OUTPUT'), 
    ['-A OUTPUT -d 192.168.15.1/32 -i eth0 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT'],
    "Get full chain rule set.",
  ],
  [
    $ipt->save_table(), 
    ['-A OUTPUT -d 192.168.15.1/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT'],
    "Get full table rule set.",
  ],
];


test($tests);

