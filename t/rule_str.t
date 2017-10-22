#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $oIPT = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $paTests = 
[
  [
    $oIPT->_srcdst({'ip' => "1.2.3.4"}),
    [],
    "Not enough parameters in srcdst",
  ],
  [
    $oIPT->_srcdst(
      {
        'ip' => "1.2.3.4",
        'direction' => "src",
      }
    ),
    [
      '-s 1.2.3.4/32'
    ],
    'Source direction IP string.',
  ],
  [
    $oIPT->_srcdst(
      {
        'ip' => "1.2.3.4",
        '!direction' => "src",
      }
    ),
    [
      '! -s 1.2.3.4/32'
    ],
    'Source direction not IP string.',
  ],
  [
    $oIPT->_srcdst(
      {
        'not' => 1,
        'ip' => "1.2.3.4",
        'direction' => "src",
      }
    ),
    [
      '! -s 1.2.3.4/32'
    ],
    'Source not key IP string.',
  ],
  [
    $oIPT->_io_if({'if' => 'eth0'}),
    [],
    "Not enough parameters in io_if",
  ],
  [
    $oIPT->_io_if(
      {
        'if' => "eth*",
        'direction' => "out",
      }
    ),
    [
      '-o eth*'
    ],
    "Out IF string",
  ],
  [
    $oIPT->_io_if(
      {
        'if' => "eth*",
        '!direction' => "out",
      }
    ),
    [
      '! -o eth*'
    ],
    "Out not IF string",
  ],
  [
    $oIPT->_io_if(
      {
        'not' => 1,
        'if' => "eth*",
        'direction' => "out",
      }
    ),
    [
      '! -o eth*'
    ],
    "Out not key IF string",
  ],
  [
    $oIPT->_proto({'proto' => "UDP"}), 
    [
      '-p udp'
    ], 
    "Protocol string"
  ],
  [
    $oIPT->_proto({'!proto' => "UDP"}), 
    [
      '! -p udp'
    ], 
    "Protocol not string"
  ],
  [
    $oIPT->_proto({'not' => 1, 'proto' => "UDP"}), 
    [
      '! -p udp'
    ], 
    "Protocol not key"
  ],
  [
    $oIPT->_owner({'name' => "testuser"}), 
    [
      '-m owner --uid-owner 359'
    ], 
    "Username"
  ],
  [
    $oIPT->_owner({'!name' => "testuser"}), 
    [
      '-m owner ! --uid-owner 359'
    ], 
    "Not username"
  ],
  [
    $oIPT->_owner({'not' => 1, 'name' => "testuser"}), 
    [
      '-m owner ! --uid-owner 359'
    ], 
    "Not key username"
  ],
  [
    $oIPT->_owner({'name' => 567}), 
    [
      '-m owner --uid-owner 567'
    ], 
    "UserID"
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP", 
        '!dport' => 80, 
        'sport' => "1024:65536"
      }
    ),
    [
      '-p tcp -m tcp --sport 1024:65536 ! --dport 80'
    ],
    "TCP not one key options",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'not' => 1,
        'name' => "TCP", 
        'dport' => 80, 
        'sport' => "1024:65536"
      }
    ),
    [
      '-p tcp -m tcp ! --sport 1024:65536 ! --dport 80'
    ],
    "TCP not key options",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        'flags' => "syn",
      }
    ),
    [
      '-p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN'
    ],
    "TCP lookup flags",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        'flags' => "ack,syn none",
      }
    ),
    [
      '-p tcp -m tcp --tcp-flags SYN,ACK NONE'
    ],
    "TCP string flags (reorder and uppercase)",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        'flags' => "ack,syn",
      }
    ),
    [
      '-p tcp -m tcp --tcp-flags SYN,ACK ALL'
    ],
    "TCP string flags - no comp",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        'flags' => [["syn,ack"],["none"]],
      }
    ),
    [
      '-p tcp -m tcp --tcp-flags SYN,ACK NONE'
    ],
    "TCP array of strings flags",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        'flags' => "syn,ack none",
      }
    ),
    [
      '-p tcp -m tcp --tcp-flags SYN,ACK NONE'
    ],
    "TCP strings of flags",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        'flags' => "syn ",
      }
    ),
    [
      '-p tcp -m tcp --tcp-flags SYN ALL'
    ],
    "TCP string of flags (syn - no comp)",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'name' => "TCP",
        '!flags' => "syn",
      }
    ),
    [
      '-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN'
    ],
    "TCP not flags",
  ],
  [
    $oIPT->_tcp_udp(
      {
        'not' => 1,
        'name' => "TCP",
        'flags' => "syn",
      }
    ),
    [
      '-p tcp -m tcp ! --tcp-flags FIN,SYN,RST,ACK SYN'
    ],
    "TCP not key flags",
  ],
  [
    $oIPT->_icmp(
      {
        'name' => "ICMP", 
        'type' => 8
      }
    ),
    [
      '-p icmp -m icmp --icmp-type 8'
    ],
    "ICMP options",
  ],
  [
    $oIPT->_icmp(
      {
        'not' => 1,
        'name' => "ICMP", 
        'type' => 8
      }
    ),
    [
      '-p icmp -m icmp ! --icmp-type 8'
    ],
    "ICMP not key options",
  ],
  [
    $oIPT->_icmp(
      {
        'name' => "ICMP", 
        '!type' => 8
      }
    ),
    [
      '-p icmp -m icmp ! --icmp-type 8'
    ],
    "ICMP not options",
  ],
  [
    $oIPT->_ct({'name' => [qw/established related/]}),
    [
      "-m conntrack --ctstate RELATED,ESTABLISHED"
    ],
    "Connection state options",
  ],
  [
    $oIPT->_ct({'!name' => [qw/established related/]}),
    [
      "-m conntrack ! --ctstate RELATED,ESTABLISHED"
    ],
    "Connection state not options",
  ],
  [
    $oIPT->_ct({'not' => 1, 'name' => [qw/established related/]}),
    [
      "-m conntrack ! --ctstate RELATED,ESTABLISHED"
    ],
    "Connection state not key options",
  ],
  [
    $oIPT->_limit(
      {
        'limit' => "5/min", 
        'burst' => "10"
      }
    ), 
    [
      '-m limit --limit 5/min --limit-burst 10'
    ],
    "Rate limit",
  ],
  [
    $oIPT->_limit({'not' => 1, limit => 5}),
    [],
    "Fail rate limit limit - can not use not",
  ],
  [
    $oIPT->_limit(
      {
        'limit' => 7, 
        'burst' => 0
      }
    ),
    [],
    "Rate limit (Invalid limit and no burst).",
  ],
  [
    $oIPT->_comment({'name' => "foo bar baz"}), 
    [
      '-m comment --comment "foo bar baz"'
    ], 
    "Comment"
  ],
  [
    $oIPT->_comment({'not' => 1, 'name' => "foo"}), 
    [], 
    "Failed comment - can not use not"
  ],
  [
    $oIPT->_jump({'name' => "test"}), 
    [
      '-j test'
    ], 
    "Jump"
  ],
  [
    $oIPT->_jump(
      {
        'name' => "LOG", 
        'prefix' => "foo", 
        'tcp' => 1, 
        'ip' => 1, 
        'uid' => 1
      }
    ),
    [
      '-j LOG --log-prefix "foo" --log-tcp-options --log-ip-options --log-uid'
    ],
    "LOG jump with options",
  ],
  [
    $oIPT->_jump(
      {
        'name' => "REJECT", 
        'with' => 1
      }
    ), 
    [
      '-j REJECT --reject-with icmp-port-unreachable'
    ], 
    "REJECT jump with icmp-port-unreachable",
  ],
  [
    $oIPT->_jump(
      {
        'name' => "CT", 
        'notrack' => 1
      }
    ), 
    [
      '-j CT --notrack'
    ], 
    "CT jump with notrack"
  ],
  [
    $oIPT->_jump(
      {
        'name' => "SNAT", 
        'src' => "1.2.3.4"
      }
    ), 
    [
      '-j SNAT --to-source 1.2.3.4/32'
    ], 
    "SNAT jump to source",
  ],
  [
    $oIPT->_jump(
      {
        'name' => "DNAT", 
        'dst' => "5.6.7.8"
      }
    ),
    [
      '-j DNAT --to-destination 5.6.7.8/32'
    ],
    "DNAT jump to destination",
  ],
  [
    $oIPT->add_list(
      'test', 
      [qw(
        1.2.3.4 
        5.6.7.8
      )], 
      {
        'hashsize' => 2048
      }
    ), 
    1, 
    "Save IPSET"
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
    $oIPT->add_list(
      'test', 
      [qw(
        1.1.1.0/24
        2.2.0.0/16
      )], 
      {
        'hashsize' => 2048
      }
    ), 
    1, 
    "Save IPSET 2"
  ],
  [
    [$oIPT->get_ipset()],
    [
      'create test hash:net family inet hashsize 2048 maxelen 65536',
      'add test 1.2.3.4/32',
      'add test 5.6.7.8/32',
      'add test 1.1.1.0/24',
      'add test 2.2.0.0/16',
    ],
    "IPSET return data 2"
  ],
];

test($paTests);
