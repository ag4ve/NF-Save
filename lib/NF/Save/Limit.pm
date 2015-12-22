package NF::Save::Limit;

use strict;
use warnings;
 
my @aMixinSubs = qw/_limit/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = ['limit' => 'limit'];
  my $paPre = [qw/proto owner match list tcp udp icmp conntrack/];
  my $paPost = [qw/comment jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# TODO I think a burst value of 0 is allowed (useless but allowed)
# Return an array of limit strings
sub _limit
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'name +imp'         => "-m limit",
        'limit +req =limit' => "--limit",
        'burst'             => "--limit-burst",
      ],
      'lookup' => {
        'limit' => '^[0-9]+\/(sec(ond)?|min(ute)?|hour|day)'
      }
    }
  )];
}


1;

