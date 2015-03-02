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
  my @aStr;
  push @aStr, "-m limit";
  (push @aStr, "--limit " . $phParams->{limit}) 
    if ($phParams->{limit} and 
      $phParams->{limit} =~ /^[0-9]+\/(sec(ond)?|min(ute)?|hour|day)/);
  (push @aStr, "--limit-burst " . $phParams->{burst}) if($phParams->{burst});
  return [join(" ", @aStr)];
}


1;

