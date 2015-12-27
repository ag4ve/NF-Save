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

Scrape a Unix password file and return a hash with user => uid

=cut

sub get_uids
{
  my ($oSelf, $sFile) = @_;
  $sFile //= '/etc/passwd';

  my ($fh, $phRet);
  if (open(my $fh, '<', $sFile))
  {
    while (my $line = <$fh>)
    {
      my @parts = split(':', $line);
      $phRet->{$parts[0]} = $parts[2];
    }
    close($fh);
    return $phRet;
  }
  else
  {
    warn "Could not read password file.\n";
    return;
  }
}

 
1;

