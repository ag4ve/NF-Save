package NF::Save::Comment;

use strict;
use warnings;
 
my @aMixinSubs = qw/_comment/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = ['comment' => 'comment'];
  my $paPre = [qw/proto owner match list tcp udp icmp conntrack limit/];
  my $paPost = [qw/jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}

# Return an array of comment strings
sub _comment
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'name +req qq' => "-m comment --comment",
      ],
    }
  )];
}


1;

