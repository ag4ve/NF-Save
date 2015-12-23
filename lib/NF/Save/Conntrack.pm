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
        'ct +imp'                 => "-m conntrack",
        'state +req &ctorder'  => "--ctstate",
      ], 
      'alt' => {
        'state' => "name",
      }, 
      'lookup' => {
        'ctorder' => sub {
          my ($sData, $sKey) = @_;
          return if (ref(\$sData) ne 'SCALAR')

          my %order = {
            'NEW'         => 0,
            'RELATED'     => 1,
            'ESTABLISHED' => 2,
          };
          return join(",",
            sort {$order{$a} <=> $order{$b}}
            split(',', uc($sData))
          );
        },
      },
    }
  )];
}

 
1;

