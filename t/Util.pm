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
#       AUTHOR:  Dr. Fritz Mehner (mn), mehner@fh-swf.de
#      COMPANY:  FH Südwestfalen, Iserlohn
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
  my ($tests) = @_;

  foreach my $test (@$tests)
  {
    eq_or_diff(@$test);
  }
  
  done_testing(scalar(@$tests));
}


1;
