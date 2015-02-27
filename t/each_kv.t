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
    [
      $oIPT->_each_kv(
        [qw/
          a 
          b 
          c 
          d
        /]
      )
    ], 
    1, 
    "Add array to iterator"
  ],
  [
    [
      $oIPT->_each_kv('keys')
    ], 
    [qw/
      a 
      c
    /], 
    "All keys"
  ],
  [
    [
      $oIPT->_each_kv('values')
    ], 
    [qw/
      b 
      d
    /], 
    "All values"
  ],
  [
    [
      $oIPT->_each_kv('keys b')
    ], 
    [qw/
      a
    /], 
    "Keys for value search"
  ],
  [
    [
      $oIPT->_each_kv('values c')
    ], 
    [qw/
      d
    /], 
    "Values for key search"
  ],
  [
    [
      $oIPT->_each_kv()
    ], 
    [qw/
      a 
      b
    /], 
    "Retured first two in list"
  ],
  [
    [
      $oIPT->_each_kv(
        [qw/
          e 
          f 
          g
        /]
      )
    ], 
    0, 
    "Add invalid array"
  ],
  [
    [
      $oIPT->_each_kv()
    ], 
    [qw/
      c 
      d
    /], 
    "Returned last two in list"
  ],
  [
    [
      $oIPT->_each_kv()
    ], 
    [], 
    "Nothing left in list"
  ],
  [
    [
      $oIPT->_each_kv(
        [qw/
          a 
          b 
          c 
          d
        /], 
        'foo'
      )
    ], 
    1, 
    "Add array to named iterator"
  ],
  [
    [
      $oIPT->_each_kv('keys', 'foo')
    ], 
    [qw/
      a 
      c
    /], 
    "All named keys"
  ],
  [
    [
      $oIPT->_each_kv(undef, 'foo')
    ], 
    [qw/
      a 
      b
    /], 
    "Retured first two in named list"
  ],
  [
    [
      $oIPT->_each_kv(undef, 'foo')
    ], 
    [qw/
      c 
      d
    /], 
    "Returned last two in named list"
  ],
  [
    [
      $oIPT->_each_kv(undef, 'foo')
    ], 
    [], 
    "Nothing left in named list"
  ],
];

test($paTests);
