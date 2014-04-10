#!perl
#
#===============================================================================
#
#         FILE:  ipt_do.t
#
#  DESCRIPTION:  
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Shawn Wilson
#      COMPANY:  
#      VERSION:  1.0
#      CREATED:  02/16/2014 07:32:30 AM
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'uids' => {'testuser' => 359}, 'useipset' => 1});

$ipt->rule('OUTPUT', {
  'udp' => {
    'sport' => "1024:65535",
    'dport' => "53",
  }, 
  'dst' => "5.6.7.8",
  'comment' => [qw/nameserver/],
  'jump' => "ACCEPT",
});
# -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT

$ipt->rule('POSTROUTING', {
  'out' => "eth0",
  'src' => "172.31.0.0/24",
  'comment' => ["VM data"],
  'jump' => {
    'name' => "LOG",
    'prefix' => "FW: masq ACCEPT",
  },
}, 'nat');
# -A POSTROUTING -s 172.31.0.0/24 -o eth0 -m comment --comment "VM data" -j LOG --log-prefix "FW: masq ACCEPT "

$ipt->rule('OUTPUT', {
  'tcp' => {
    'sport' => 20,
    'dport' => "1024:65535",,
  },
  'list' => {
    'name' => "scan_targets",
    'direction' => ['src'],
    'ipset' => 1,
  },
  'comment' => ["scan_targets_add"],
  'jump' => "ACCEPT",
});
# -A OUTPUT -m set --match-set scan_targets src -m tcp -p tcp --sport 20 --dport 1024:65535 -m comment --comment "scan_targets_add" -j ACCEPT

$ipt->rule('FORWARD', {
  'in' => "eth0",
  'out' => "eth1",
  'match' => {
    '!name' => 'TCP',
  },
  'comment' => ["VM data"],
  'jump' => 'RETURN',
});
# -A FORWARD -i eth0 -o eth1 -m ! tcp -m comment --comment "VM data" -j RETURN

$ipt->comment("Some comment");

$ipt->ipset('scan_targets', [qw/1.2.3.4 5.6.7.8/], {'hashsize' => 2048});

my $tests = [
  [
    $ipt->save(),
    [
      '# Some comment',
      '*raw',
      ':PREROUTING ACCEPT [0:0]',
      ':OUTPUT ACCEPT [0:0]',
      'COMMIT',
      '*nat',
      ':PREROUTING ACCEPT [0:0]',
      ':INPUT ACCEPT [0:0]',
      ':OUTPUT ACCEPT [0:0]',
      ':POSTROUTING ACCEPT [0:0]',
      '-A POSTROUTING -s 172.31.0.0/24 -o eth0 -m comment --comment "VM data" -j LOG --log-prefix "FW: masq ACCEPT "',
      'COMMIT',
      '*mangle',
      ':PREROUTING ACCEPT [0:0]',
      ':INPUT ACCEPT [0:0]',
      ':FORWARD ACCEPT [0:0]',
      ':OUTPUT ACCEPT [0:0]',
      ':POSTROUTING ACCEPT [0:0]',
      'COMMIT',
      '*filter',
      ':INPUT DROP [0:0]',
      ':FORWARD DROP [0:0]',
      ':OUTPUT DROP [0:0]',
      '-A OUTPUT -d 127.0.0.1/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT',
      '-A OUTPUT -m set --match-set scan_targets src -m tcp -p tcp --sport 20 --dport 1024:65535 -m comment --comment "scan_targets_add" -j ACCEPT',
      '-A FORWARD -i eth0 -o eth1 -m ! tcp -m comment --comment "VM data" -j RETURN',
      'COMMIT',
    ],
    "Retrieve full iptables-save output",
  ]
];

test($tests);

