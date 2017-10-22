package NF::Save::TCP_UDP;

use strict;
use warnings;

use Data::Dumper;
 
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
        'name +req lc'              => "-p",
        'name +req lc'              => "-m",
        'sport +not'                => "--sport",
        'dport +not'                => "--dport",
        'flags +not %flags &order'  => "--tcp-flags",
      ], 
      'alt' => {
        "name" => 'key',
      }, 
      'check' => [
      ],
      'lookup' => {
        'flags' => $oSelf->{flags},
        'order' => sub {
          my ($oData, $sKey) = @_;
          my $paData = [['ALL'], ['ALL']];
          my %order = (
            'FIN'   => 0,
            'SYN'   => 1,
            'RST'   => 2,
            'PSH'   => 3,
            'ACK'   => 4,
            'URG'   => 5,
            'ALL'   => 6,
            'NONE'  => 7,
          );
          my $sFlags_ex = join('|', keys %order);

          if (ref($oData) eq 'ARRAY')
          {
            foreach my $i (0 .. $#{$oData})
            {
              if (ref($oData->[$i]) eq 'SCALAR')
              {
                $paData->[$i] = [split(',', uc($oData->[$i]))];
              }
              elsif (ref($oData->[$i]) eq 'ARRAY')
              {
                @{$paData->[$i]} = map {uc($_)} @{$oData->[$i]};
              }
            }
          }
          elsif (ref(\$oData) eq 'SCALAR')
          {
            if ($oData !~ /($sFlags_ex)/i)
            {
              return $oData;
            }
            my @aFlagList = $oData =~ /([^ ]+) ?/g;
            foreach my $i (0 .. $#aFlagList)
            {
              $paData->[$i] = [split(',', uc($aFlagList[$i]))];
            }
          }

          foreach my $i (0, 1)
          {
            if (grep {$_ !~ /($sFlags_ex)/} @{$paData->[$i]})
            {
              warn "Unknown flags in " . Dumper($oData) . "\n";
            }
            elsif (scalar(@{$paData->[0]}) > 1 and
              grep {$_ eq 'ALL' or $_ eq 'NONE'} @{$paData->[$i]})
            {
              warn "Improper flags in " . Dumper($oData) . "\n";
            }
          }
          return join(" ",
            map {
              join(",",
                sort {$order{$a} <=> $order{$b}} @$_
              )
            } @$paData
          );
        },
      },
    },
  )];
}

 
1;

