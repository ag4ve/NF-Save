package NF::Save::Conntrack;

use strict;
use warnings;
 
my @aMixinSubs = qw/_ct/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = ['conntrack' => 'ct'];
  my $paPre = [qw/proto owner match list tcp udp icmp/];
  my $paPost = [qw/limit comment jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# Return an array of conntrack strings
sub _ct
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'ct +imp'                     => "-m conntrack",
        'state +req +not uc &ctorder' => "--ctstate",
      ], 
      'alt' => {
        'state' => "name",
      }, 
      'lookup' => {
        'ctorder' => sub {
          my ($oData, $sKey) = @_;
          my @aData;

          if (ref(\$oData) eq 'SCALAR')
          {
            @aData = split(',', uc($oData));
          }
          elsif (ref($oData) eq 'ARRAY')
          {
            @aData = map {uc($_)} @$oData;
          }

          my %order = (
            'NEW'         => 0,
            'RELATED'     => 1,
            'ESTABLISHED' => 2,
          );
          return join(",",
            sort {$order{$a} <=> $order{$b}}
            @aData
          );
        },
      },
    }
  )];
}

 
1;

