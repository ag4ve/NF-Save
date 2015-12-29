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
    [$oIPT->_str_map_transform('test', '%foo', {
      'foo' => {
        'test' => "aaa",
      },
    })],
    ['aaa'],
    "_str_map_transform hash.",
  ],
  [
    [$oIPT->_str_map_transform('test foo', '=foo', {
      'foo' => '^test foo$',
    })],
    ['test foo'],
    "_str_map_transform regex.",
  ],
  [
    [$oIPT->_str_map_transform('test', '&foo', {
      'foo' => sub {
        return "$_[0] foo";
      },
    })],
    ['test foo'],
    "_str_map_transform sub.",
  ],
  [
    [$oIPT->_str_map_transform('TEST', 'lc')],
    ['test'],
    "_str_map_transform lc.",
  ],
  [
    [$oIPT->_str_map_transform('test', 'uc')],
    ['TEST'],
    "_str_map_transform uc.",
  ],
  [
    [$oIPT->_str_map_transform('test', 'qq')],
    ['"test"'],
    "_str_map_transform uc.",
  ],
  [
    [$oIPT->_str_map_transform('1.2.3.4', 'ip')],
    ['1.2.3.4/32'],
    "_str_map_transform ip.",
  ],
  [
    [$oIPT->_str_map_transform(undef, 'lc')],
    [],
    "_str_map_transform no data.",
  ],
  [
    [$oIPT->_str_map_transform('test', 'foo')],
    ['test'],
    "_str_map_transform unknown function.",
  ],
  [
    [$oIPT->_str_map_transform('test')],
    ['test'],
    "_str_map_transform no mapfunc.",
  ],
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
