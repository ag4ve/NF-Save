package NF::Save::Comment;

use strict;
use warnings;
 
my @aMixinSubs = qw/_comment/;

sub Init
{
  my ($oSelf) = @_;

  use Data::Dumper;
  no strict 'refs';
  my $paLookup = ['comment' => 'comment'];
  my $paPre = [qw/proto owner match list tcp udp icmp conntrack limit/];
  my $paPost = [qw/jump/];

  return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
}

# Return an array of comment strings
sub _comment
{
  my ($oSelf, $phParams) = @_;

  my @aParts;
  if (ref($phParams->{name}) eq 'ARRAY' and scalar(@{$phParams->{name}}))
  {
    push @aParts, @{$phParams->{name}};
  }
  elsif (ref(\$phParams->{name}) eq 'SCALAR' and length($phParams->{name}))
  {
    push @aParts, $phParams->{name};
  }
  else
  {
    return;
  }

  return ["-m comment --comment \"" . join(" ", grep {defined($_)} @aParts) . "\""];
}

