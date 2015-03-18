#
#===============================================================================
#
#         FILE:  Util.pm
#
#  DESCRIPTION:  
#
#        FILES:  ---
#         BUGS:  ---
#        NOTES:  ---
#       AUTHOR:  Shawn Wilson <swilson@korelogic.com>
#      COMPANY:  Korelogic
#      VERSION:  1.0
#      CREATED:  02/16/2014 06:41:31 AM
#     REVISION:  ---
#===============================================================================

use strict;
use warnings;

use Test::More;
use Test::Differences;

sub test
{
  my ($paTests) = @_;

  foreach my $paTest (@$paTests)
  {
    eq_or_diff(@$paTest);
  }
  
  done_testing(scalar(@$paTests));
}


1;
