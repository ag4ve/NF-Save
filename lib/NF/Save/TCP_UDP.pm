package NF::Save::TCP_UDP;

use strict;
use warnings;
 
my @aMixinSubs = qw/_tcp_udp/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = [
    'tcp' => 'tcp_udp',
    'udp' => 'tcp_udp',
  ];
  my $paPre = [qw/proto owner match list/];
  my $paPost = [qw/icmp conntrack limit comment jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# Return an array of TCP or UDP protocol match strings
sub _tcp_udp
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'name +req lc'      => "-p",
        'name +req lc'      => "-m",
        'sport +not'        => "--sport",
        'dport +not'        => "--dport",
        'flags +not %flags' => "--tcp-flags",
      ], 
      'alt' => {
        'name' => "key"
      }, 
      'lookup' => {
        'flags' => $oSelf->{flags}
      },
    },
  )];
}

 
1;

