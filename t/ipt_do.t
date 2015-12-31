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

my $oIPT = NF::Save->new(
  {
    'UIDs'      => 
    {
      'testuser'  => 359,
    },
    'UseIPSET'  => 1,
    'Policy'    =>
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

$oIPT->rule(
  'OUTPUT', 
  {
    'udp' => 
    {
      'sport' => "1024:65535",
      'dport' => "53",
    }, 
    'dst' => "5.6.7.8",
    'comment' => [qw/nameserver/],
    'jump' => "ACCEPT",
  }
);
# -A OUTPUT -d 127.0.0.1/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT

$oIPT->rule(
  'POSTROUTING', 
  {
    'out' => "eth0",
    'src' => {
      'name' => "172.31.0.0/24",
      'not' => 1,
    },
    'comment' => ["VM data"],
    'jump' => 
    {
      'name' => "LOG",
      'prefix' => "FW: masq ACCEPT ",
    },
  }, 
  'nat'
);
# -A POSTROUTING ! -s 172.31.0.0/24 -o eth0 -m comment --comment "VM data" -j LOG --log-prefix "FW: masq ACCEPT "

$oIPT->rule(
  'OUTPUT', 
  {
    'tcp' => 
    {
      '!sport' => 20,
      'dport' => "1024:65535",,
    },
    'list' => 
    {
      'name' => "scan_targets",
      'direction' => ['src'],
    },
    'comment' => ["scan_targets_add"],
    'jump' => "ACCEPT",
  }
);
# -A OUTPUT -m set --match-set scan_targets src -m tcp -p tcp ! --sport 20 --dport 1024:65535 -m comment --comment "scan_targets_add" -j ACCEPT

$oIPT->rule(
  'FORWARD', 
  {
    'in' => "eth0",
    'out' => "eth1",
    'proto' => 
    {
      '!name' => 'TCP',
    },
    'comment' => ["VM data"],
    'jump' => 'RETURN',
  }
);
# -A FORWARD -i eth0 -o eth1 -m ! tcp -m comment --comment "VM data" -j RETURN

$oIPT->comment("Some comment");

$oIPT->add_list(
  'scan_targets', 
  [qw/
    1.2.3.4 
    5.6.7.8
  /], 
  {
    'hashsize' => 2048
  }
);

my $paTests = 
[
  [
    [
      $oIPT->get_tables()
    ], 
    [qw/
      nat 
      filter
    /], 
    "Tables returned in the correct order."
  ],
  [
    [
      $oIPT->save()
    ],
    [
      '*nat',
      ':PREROUTING ACCEPT [0:0]',
      ':INPUT ACCEPT [0:0]',
      ':OUTPUT ACCEPT [0:0]',
      ':POSTROUTING ACCEPT [0:0]',
      '-A POSTROUTING ! -s 172.31.0.0/24 -o eth0 -m comment --comment "VM data" -j LOG --log-prefix "FW: masq ACCEPT "',
      'COMMIT',
      '*filter',
      ':INPUT DROP [0:0]',
      ':FORWARD DROP [0:0]',
      ':OUTPUT DROP [0:0]',
      '-A FORWARD -i eth0 -o eth1 ! -p tcp -m comment --comment "VM data" -j RETURN',
      '-A OUTPUT -d 5.6.7.8/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT',
      '-A OUTPUT -m set --match-set scan_targets src -p tcp -m tcp ! --sport 20 --dport 1024:65535 -m comment --comment "scan_targets_add" -j ACCEPT',
      'COMMIT',
      '# Some comment',
    ],
    "Retrieve full iptables-save output",
  ],
  [
    $oIPT->useipset(),
    1,
    "Currently using ipset.",
  ],
  [
    $oIPT->useipset(0),
    0,
    "Disable ipset.",
  ],
  [
    [
      $oIPT->save()
    ],
    [
      '*nat',
      ':PREROUTING ACCEPT [0:0]',
      ':INPUT ACCEPT [0:0]',
      ':OUTPUT ACCEPT [0:0]',
      ':POSTROUTING ACCEPT [0:0]',
      '-A POSTROUTING ! -s 172.31.0.0/24 -o eth0 -m comment --comment "VM data" -j LOG --log-prefix "FW: masq ACCEPT "',
      'COMMIT',
      '*filter',
      ':INPUT DROP [0:0]',
      ':FORWARD DROP [0:0]',
      ':OUTPUT DROP [0:0]',
      '-A FORWARD -i eth0 -o eth1 ! -p tcp -m comment --comment "VM data" -j RETURN',
      '-A OUTPUT -d 5.6.7.8/32 -p udp -m udp --sport 1024:65535 --dport 53 -m comment --comment "nameserver" -j ACCEPT',
      '-A OUTPUT -s 1.2.3.4/32 -p tcp -m tcp ! --sport 20 --dport 1024:65535 -m comment --comment "scan_targets_add" -j ACCEPT',
      '-A OUTPUT -s 5.6.7.8/32 -p tcp -m tcp ! --sport 20 --dport 1024:65535 -m comment --comment "scan_targets_add" -j ACCEPT',
      'COMMIT',
      '# Some comment',
    ],
    "Retrieve full iptables-save output with a disabled ipset",
  ],
  [
    $oIPT->useipset(),
    0,
    "Currently not using ipset.",
  ],
];

test($paTests);

# '*raw',
# ':PREROUTING ACCEPT [0:0]',
# ':OUTPUT ACCEPT [0:0]',
# 'COMMIT',
# '*nat',
# ':PREROUTING ACCEPT [0:0]',
# ':INPUT ACCEPT [0:0]',
# ':OUTPUT ACCEPT [0:0]',
# ':POSTROUTING ACCEPT [0:0]',
# 'COMMIT',
# '*mangle',
# ':PREROUTING ACCEPT [0:0]',
# ':INPUT ACCEPT [0:0]',
# ':FORWARD ACCEPT [0:0]',
# ':OUTPUT ACCEPT [0:0]',
# ':POSTROUTING ACCEPT [0:0]',
# 'COMMIT',
# '*filter',
# ':INPUT DROP [0:0]',
# ':FORWARD DROP [0:0]',
# ':OUTPUT DROP [0:0]',
# 'COMMIT',
