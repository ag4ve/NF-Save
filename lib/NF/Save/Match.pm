package NF::Save::Match;

use strict;
use warnings;
 
my @aMixinSubs = qw/_match/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = ['match' => 'match'];
  my $paPre = [qw/proto owner/];
  my $paPost = [qw/list tcp udp icmp conntrack limit comment jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# Return an array of match strings
sub _match
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'name +req lc' => "-m",
      ],
    },
  )];
}

 
1;

