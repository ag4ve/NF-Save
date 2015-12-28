#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $oIPT = NF::Save->new(
  {
    'UIDs' => 
    {
      'testuser' => 359
    }
  }
);

my $paTests = 
[
  [
    [$oIPT->_param_str()],
    [],
    "_param_str() nothing defined.",
  ],
  [
    [$oIPT->_param_str('foo')],
    [],
    "_param_str() value not defined.",
  ],
  [
    [$oIPT->_param_str(['bar'], 'foo')],
    [],
    "_param_str() key is not a scalar.",
  ],
];

test($paTests);
