#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $oIPT = NF::Save->new(
  {
    'UIDs'    => 
    {
      'testuser'  => 359,
    },
    'Policy'  =>
    {
      'filter'    =>
      {
        'INPUT'       => 'DROP',
        'OUTPUT'      => 'DROP',
        'FORWARD'     => 'DROP',
      },
    }
  }
);

my $phStruct = 
{
  'in' => "eth0",
  'udp' => 
  {
    'sport' => "1024:65535",
    'dport' => "53",
  }, 
  'dst' => "192.168.15.1",
  'comment' => [qw/nameserver/],
  'jump' => "ACCEPT",
};

my $paAssembled = 
[
  [
    '-d 192.168.15.1/32'
  ],
  [
    '-i eth0'
  ],
  [
    '-p udp -m udp --sport 1024:65535 --dport 53'
  ],
  [
    '-m comment --comment "nameserver"'
  ],
  [
    '-j ACCEPT'
  ],
];

$oIPT->rule('OUTPUT', $phStruct);

my $paTests = 
[
  [
    [$oIPT->rule('OUTPUT', $phStruct, undef, 'foo')],
    [],
    "Bad function for rule().",
  ],
  [
    [$oIPT->is_table('filter')], 
    [1], 
    "Table filter exists.",
  ],
  [
    [$oIPT->is_table('foobar')], 
    [0], 
    "Table foobar does not exist.",
  ],
  [
    [$oIPT->is_chain('OUTPUT')], 
    [1], 
    "Chain OUTPUT exists.",
  ],
  [
    [$oIPT->is_chain('OUTPUT', 'filter')], 
    [1], 
    "Chain OUTPUT in table filter exists.",
  ],
  [
    [$oIPT->is_chain('OUTPUT', 'foobar')], 
    [0], 
    "Chain OUTPUT in table foobar does not exist.",
  ],
  [
    [$oIPT->is_chain('foobar', 'filter')], 
    [0], 
    "Chain foobar in table filter exists.",
  ],
  [
    [$oIPT->get_chains('filter')], 
    [
      'INPUT',
      'FORWARD',
      'OUTPUT',
    ],
    "Get chains from filter.",
  ],
  [
    $oIPT->get_rules('OUTPUT'), 
    $phStruct, 
    "Get stored rules from OUTPUT.",
  ],
  [
    $oIPT->get_rules('OUTPUT', 'filter'), 
    $phStruct, 
    "Get stored rules from OUTPUT chain in filter table.",
  ],
  [
    [$oIPT->get_rules('INPUT', 'filter')], 
    [], 
    "Get stored rules from INPUT chain in filter table (undef).",
  ],
  [
    $oIPT->get_policy('INPUT'), 
    'DROP', 
    "Policy for INPUT in an (unspecified) filter table.",
  ],
  [
    $oIPT->get_policy('OUTPUT', 'filter'), 
    'DROP', 
    "Policy for OUTPUT in the filter table.",
  ],
  [
    $oIPT->get_policy('OUTPUT', 'mangle'), 
    'ACCEPT', 
    "Policy for OUTPUT in the mangle table.",
  ],
  [
    [$oIPT->get_policy('foobar', 'mangle')], 
    [], 
    "Policy for foobar in the mangle table (undef).",
  ],
  [
    $oIPT->get_header('OUTPUT'), 
    ':OUTPUT DROP [0:0]', 
    "Header for OUTPUT in an (unspecified) filter table.",
  ],
  [
    $oIPT->get_header('OUTPUT', 'filter'), 
    ':OUTPUT DROP [0:0]', 
    "Header for OUTPUT in the filter table.",
  ],
  [
    $oIPT->get_header('OUTPUT', 'mangle'), 
    ':OUTPUT ACCEPT [0:0]', 
    "Header for OUTPUT in the mangle table.",
  ],
  [
    $oIPT->get_header('foobar'), 
    ':foobar - [0:0]', 
    "Header for the foobar chain.",
  ],
  [
    $oIPT->is_user('testuser'),
    1,
    "User testuser exists.",
  ],
  [
    $oIPT->is_user('foobar'),
    0,
    "User foobar does not exist.",
  ],
  [
    $oIPT->check_rule($phStruct),
    1,
    "Rule checks ok.",
  ],
  [
    $oIPT->check_rule({%$phStruct, 'bad' => 'data'}),
    0,
    "Rule checks bad.",
  ],
  [
    $oIPT->get(), 
    {
      'filter' => 
      {
        'INPUT' => [], 
        'FORWARD' => [], 
        'OUTPUT' => [$phStruct],
      }
    }, 
    "Same structures.",
  ],
  [
    $oIPT->assemble($phStruct), 
    $paAssembled, 
    "Assemble rule.",
  ],
  [
    $oIPT->save_chain('OUTPUT'), 
    [
      '-A OUTPUT -d 192.168.15.1/32 -i eth0 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT'
    ],
    "Get full chain rule set.",
  ],
  [
    $oIPT->save_table(), 
    [
      ':INPUT DROP [0:0]',
      ':FORWARD DROP [0:0]',
      ':OUTPUT DROP [0:0]',
      '-A OUTPUT -d 192.168.15.1/32 -i eth0 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT',
    ],
    "Get full table rule set.",
  ],
];


test($paTests);

