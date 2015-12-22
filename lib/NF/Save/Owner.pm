package NF::Save::Owner;

use strict;
use warnings;
 
my @aMixinSubs = qw/_owner get_uids/;

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

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'owner +imp'            => "-m owner",
        'name +req +not %owner' => "--uid-owner",
      ], 
      'lookup' => {
        'owner' => $oSelf->{uids}
      },
    }
  )];
}

=head2 get_uids()

Populate the module's UID hash with user => uid

=cut

sub get_uids
{
  my ($oSelf) = @_;

  my $fh;
  if (open(my $fh, '<', '/etc/passwd'))
  {
    while (my $line = <$fh>)
    {
      my @parts = split(':', $line);
      $oSelf->{uids}{$parts[0]} = $parts[2];
    }
    close($fh);
    return 1;
  }
  else
  {
    warn "Could not read password file.\n";
  }
}

 
1;

