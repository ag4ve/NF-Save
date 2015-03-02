package NF::Save::Owner;

use strict;
use warnings;
 
my @aMixinSubs = qw/_owner/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = ['owner' => 'owner'];
  my $paPre = [qw/proto/];
  my $paPost = [qw/match list tcp udp icmp conntrack limit comment jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# Return an array of owner strings
sub _owner
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
      'name bool'        => "-m owner",
      'owner %owner' => "--uid-owner",
    ], {
      'owner' => "name",
    }, [qw/
      owner
    /], {
      "owner" => $oSelf->{uids}
    }
  )];
}

 
1;

