#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'uids' => {'testuser' => 359}});

my $tests = [
  [$ipt->_str_map({
      'direction' => "src",
      'if' => "eth*",
    }, [
      'direction' => {
        'src' => "-s",
        'dst' => "-d",
     },
     'if' => "",,
  ]), '-s eth*', "Basic str_map"],
];

test($tests);
