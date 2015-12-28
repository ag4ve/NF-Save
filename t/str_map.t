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
          'foo' => "aaa",
        },
        {
          'map' => [
            'foo' => '-f',
          ],
        },
      ),
    ],
    ['-f aaa'],
    "Single key - single map"
  ],
  [
    [
      $oIPT->_str_map(
        {
          'bar' => "bbb",
        },
        {
          'map' => [
            'foo +req' => '-f',
          ],
          'alt' => {
            'foo' => "bar",
          }
        },
      ),
    ],
    ['-f bbb'],
    "Mapped to a required key."
  ],
  [
    [
      $oIPT->_str_map(
        {
          '!foo' => "aaa",
        },
        {
          'map' => [
            'foo +not' => '-f',
          ],
        },
      ),
    ],
    ['! -f aaa'],
    "Not (!) allowed."
  ],
  [
    [
      $oIPT->_str_map(
        {
          '!foo' => "aaa",
        },
        {
          'map' => [
            'foo' => '-f',
          ],
        },
      ),
    ],
    [],
    "Not (!) not allowed."
  ],
  [
    [
      $oIPT->_str_map(
        {
          'baz' => "ccc",
        },
        {
          'map' => [
            'foo' => '-f',
          ],
        },
      ),
    ],
    [],
    "Param value does not exist - no value is required."
  ],
  [
    [
      $oIPT->_str_map(
        {
          'foo' => "aaa",
        },
        {
          'map' => [
            'foo +imp' => '-f',
          ],
        },
      ),
    ],
    ['-f aaa'],
    "Implied - param given."
  ],
  [
    [
      $oIPT->_str_map(
        {},
        {
          'map' => [
            'foo +imp' => '-f',
          ],
        },
      ),
    ],
    ['-f'],
    "Implied - no param given."
  ],
  [
    [
      $oIPT->_str_map(
        {
          'foo' => "aaa",
          'bar' => "bbb",
        },
        {
          'map' => [
            'foo +req' => '-f',
          ],
          'alt' => {
            'foo' => "bar",
          }
        },
      ),
    ],
    [],
    "Duplicate key from alt - fail."
  ],
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
    "io_if type str_map."
  ],
];

test($paTests);
