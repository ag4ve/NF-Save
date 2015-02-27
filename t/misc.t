#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'UIDs' => {'testuser' => 359}});

my $tests = 
[
  [
    [
      $ipt->_sortpre(
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
      $ipt->_check_type(
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
      $ipt->_check_type(
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
      $ipt->_check_type(
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
      $ipt->_check_type(
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
      $ipt->_check_type(
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
      $ipt->_check_type(
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
      $ipt->_check_type(
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


test($tests);

