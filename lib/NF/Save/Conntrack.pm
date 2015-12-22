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

  # Define the order connection types should be listed in
  $oSelf->{ctorder} = [qw/NEW RELATED ESTABLISHED INVALID/] if (not exists($oSelf->{ctorder}));

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# Return an array of conntrack strings
sub _ct
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'name +imp'           => "-m conntrack",
        'state +req @ctorder' => "--ctstate",
      ], 
      'alt' => {
        'state' => "name",
      }, 
      'lookup' => {
        'state' => $oSelf->{ctorder}
      },
    }
  )];
}

 
1;

