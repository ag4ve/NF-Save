#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $oIPT = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $paTests = 
[
  [
    [
      $oIPT->_str_map(
        {
          'direction' => "src",
          'if' => "eth*",
        }, 
        {
          'map' => [
            'direction' => 
            {
              'src' => "-s",
              'dst' => "-d",
            },
            'if' => "",
          ],
        },
      )
    ], 
    [
      '-s eth*'
    ], 
    "Basic str_map"
  ],
];

test($paTests);
