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
  my @order = qw/NEW RELATED ESTABLISHED INVALID/;

  my @aCTState;
  if (ref($phParams->{name}) eq 'ARRAY')
  {
    @aCTState = @{$phParams->{name}};
  }
  elsif (ref(\$phParams->{name}) eq 'SCALAR')
  {
    @aCTState = split(' ', $phParams->{name});
  }

  my @aStr;
  push @aStr, "-m conntrack";
  (push @aStr, "--ctstate " . join(',', 
    map {
      my $unit = $_;
      grep {$unit eq $_} map {uc($_)} @aCTState;
    } @order))
    if (scalar(@aCTState));
  return [join(" ", @aStr)];
}

 
1;

