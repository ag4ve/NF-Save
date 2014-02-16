use strict;
use warnings;

use lib 't';
use Util;

use Test::More;

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
  [$ipt->get(), {'filter' => {'OUTPUT' => [$struct]}}, 'Same structures'],
  [$ipt->_valid_cidr('5.6.7.8/28'), 0, "Invalid subnet"],
  [$ipt->_valid_cidr('1.2.3.0/24'), 1, "Valid subnet"],
  [$ipt->_cidr_ip('1.2.3.4/32'), '1.2.3.4/32', "Valid IP with mask"],
  [$ipt->_cidr_ip('1.2.3.4'), '1.2.3.4/32', "Valid IP without a mask"],
  [$ipt->_valid_ip('5.6.7.892'), undef, "Invalid IP"],
  [$ipt->_valid_ip('5.6.7.8/29'), '5.6.7.8/29', "Valid IP"],
  [$ipt->_valid_ip('5.6.7.8'), '5.6.7.8/32', "Valid IP no CIDR"],
  [
    $ipt->_srcdst({
      'not' => 1,
      'ip' => "1.2.3.4",
      'direction' => "src",
    }),
    ['! -s 1.2.3.4'],
    'Source IP string.',
  ],
  [
    $ipt->_srcdst({'not' => 1}),
    undef,
    "Not enough parameters",
  ],
  [
    $ipt->_io_if({
      'not' => 0,
      'if' => "eth*",
      'direction' => "out",
    }),
    ['-o eth*'],
    "Source IF string",
  ],
  [$ipt->_proto({'proto' => "UDP"}), ['-p udp'], "Protocol string"],
  [$ipt->_owner({'name' => "testuser"}), ['-m owner --uid-owner 359'], "Username"],
  [$ipt->_owner({'name' => 567}), ['-m owner --uid-owner 567'], "UserID"],
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
    $ipt->_tcp_udp({'name' => "TCP", 'not' => 1, 'dport' => 80, 'sport' => "1024:65536"}),
    ['! -p tcp -m tcp --sport 1024:65536 --dport 80'],
    "TCP options",
  ],
  [
    $ipt->_icmp({'name' => "ICMP", 'not' => 1, 'type' => 8}),
    ['! -p icmp -m icmp --icmp-type 8'],
    "ICMP options",
  ],
  [
    $ipt->_ct({'name' => "established related"}),
    ["-m conntrack --ctstate RELATED,ESTABLISHED"],
    "Connection state options",
  ],
  [
    $ipt->_limit({'limit' => "5/min", 'burst' => "10"}), 
    ['-m limit --limit 5/min --limit-burst 10'],
    "Rate limit",
  ],
  [
    $ipt->_limit({'limit' => 7, 'burst' => 0}),
    ['-m limit'],
    "Rate limit (Invalid limit and no burst).",
  ],
  [$ipt->_comment({'name' => "foo bar baz"}), ['-m comment --comment "foo bar baz"'], "Comment"],
  [$ipt->_jump({'name' => "test"}), ['-j test'], "Jump"],
  [
    $ipt->_jump({'name' => "LOG", 'prefix' => "foo", 'tcp' => 1, 'ip' => 1, 'uid' => 1}),
    ['-j LOG --log-prefix "foo" --log-tcp-options --log-ip-options --log-uid'],
    "LOG jump with options",
  ],
  [
    $ipt->_jump({'name' => "REJECT", 'with' => 1}), 
    ['-j REJECT --reject-with icmp-port-unreachable'], 
    "REJECT jump with icmp-port-unreachable",
  ],
  [$ipt->_jump({'name' => "CT", 'notrack' => 1}), ['-j CT --notrack'], "CT jump with notrack"],
  [
    $ipt->_jump({'name' => "SNAT", 'src' => "1.2.3.4"}), 
    ['-j SNAT --to-source 1.2.3.4/32'], 
    "SNAT jump to source",
  ],
  [
    $ipt->_jump({'name' => "DNAT", 'dst' => "5.6.7.8"}),
    ['-j DNAT --to-destination 5.6.7.8/32'],
    "DNAT jump to destination",
  ],
  [
    $ipt->assemble($struct),
    ['-A OUTPUT -p UDP --sport 1024:65535 -d 192.168.15.1 --dport 53 -j ACCEPT -m comment --comment "nameserver"'],
    "Assemble rule",
  ],
];



# $t->save();
# [-A OUTPUT -p UDP --sport 1024:65535 -d 192.168.15.1 --dport 53 -j ACCEPT -m comment --comment "nameserver"]


test($tests);

