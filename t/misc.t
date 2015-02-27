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
      $oIPT->_sortpre(
        [qw/
          x 
          a 
          d
        /],
        [qw/
          d 
          a 
          z 
          x
        /]
      )
    ],
    [qw/
      d 
      a 
      x
    /],
    "Sort list in with a rule."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          HASH 
          ARRAY
        /], 
        '>', 
        undef, 
        1, 
        (
          {}
        )
      )
    ],
    [
      1
    ],
    "Check hash type."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          ARRAY 
          ARRAY
        /], 
        '>', 
        undef, 
        1, 
        (
          []
        )
      )
    ],
    [
      1
    ],
    "Check array type."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          HASH 
          ARRAY
        /], 
        '>', 
        undef, 
        1, 
        (
          {}, 
          [], 
          []
        )
      )
    ],
    [],
    "Check more data than types."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          HASH 
          ARRAY
        /], 
        '<', 
        undef, 
        1, 
        (
          {}
        )
      )
    ],
    [],
    "Check more types than data."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          HASH 
          ARRAY
        /], 
        '=', 
        undef, 
        1, 
        (
          {}
        )
      )
    ],
    [],
    "Check types not equal to data."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          HASH 
          ARRAY
        /], 
        undef, 
        undef, 
        1, 
        (
          {}, 
          []
        )
      )
    ],
    [
      1
    ],
    "Check types equal to data."
  ], 
  [
    [
      $oIPT->_check_type(
        [qw/
          HASH 
          ARRAY
        /], 
        undef, 
        undef, 
        0, 
        (
          undef, 
          []
        )
      )
    ],
    [
      1
    ],
    "Check allow undef."
  ]
];


test($paTests);

