package NF::Save::ListSet;

use strict;
use warnings;
 
my @aMixinSubs = qw/_list_set/;

sub Init
{
  my ($oSelf) = @_;

  my $paLookup = ['list' => 'list_set'];
  my $paPre = [qw/proto owner match/];
  my $paPost = [qw/tcp udp icmp conntrack limit comment jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}
 
# Return an array of IP address match strings or a set name
sub _list_set
{
  my ($oSelf, $phParams) = @_;

  my $sName = $phParams->{name};
  my @aRet;

  my %hDirection;
  if (ref(\$phParams->{direction}) eq 'SCALAR')
  {
    %hDirection = map {$_ => 1} split(" ", $phParams->{direction});
  }
  elsif (ref($phParams->{direction}) eq 'ARRAY')
  {
    %hDirection = map {$_ => 1} @{$phParams->{direction}};
  }
  else
  {
    warn "Direction not defined - applying filter in both directions";
    %hDirection = (
      'src' => 1,
      'dst' => 1,
    );
  }

  if (($phParams->{useipset} and $phParams->{useipset} != 0) or 
    ($oSelf->{useipset} and $oSelf->{useipset} != 0))
  {
    warn "Set [$sName] has not been defined\n" if (not $oSelf->is_ipset($sName));
    push @aRet, "-m set --match-set $sName " . join(",", sort {$b cmp $a} keys(%hDirection));
  }
  else
  {
    if (not exists($oSelf->{ipset}{$sName}{list}) and
      ref($oSelf->{ipset}{$sName}{list}) ne 'ARRAY')
    {
      warn "No list of name [$sName]\n";
      return;
    }
    my @aList = @{$oSelf->{ipset}{$sName}{list}}; 
    if (exists($hDirection{src}))
    {
      push @aRet, map {"-s $_"} @aList;
    }
    if (exists($hDirection{dst}))
    {
      push @aRet, map {"-d $_"} @aList;
    }
  }

  return [@aRet];
}

 
1;

