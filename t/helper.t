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
    [$oIPT->_return_valid_param('foo', {
      'foo'   => 1,
      '!foo'  => 1,
    })],
    [],
    "_return_valid_param() similar values.",
  ],
  [
    [$oIPT->_return_valid_param('baz', {
      'foo' => 1,
      'bar' => 1,
    })],
    [],
    "_return_valid_param() no matching values.",
  ],
  [
    [$oIPT->_return_valid_param('foo', {
      'foo' => 1,
      'bar' => 1,
    })],
    ['foo'],
    "_return_valid_param() value matches.",
  ],
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
  [
    [$oIPT->_param_str('bar', 'foo')],
    [
      {
        'name'  => "foo",
        'key'   => "bar",
      },
    ],
    "_param_str() value is a scalar.",
  ],
  [
    [$oIPT->_param_str('bar', ['foo', 'baz'])],
    [
      {
        'name'  => "foo baz",
        'key'   => "bar",
      },
    ],
    "_param_str() value is an array.",
  ],
  [
    [$oIPT->_param_str('bar', {'foo' => "aaa"})],
    [
      {
        'foo'   => "aaa",
        'key'   => "bar",
      },
    ],
    "_param_str() value is a hash.",
  ],
  [
    [$oIPT->_param_str('bar', {'foo' => "aaa", 'key' => "bbb"})],
    [
      {
        'foo'   => "aaa",
        'key'   => "bbb",
      },
    ],
    "_param_str() value is a hash and 'key' is given.",
  ],
  [
    [$oIPT->_comp()],
    [],
    "_comp() nothing defined.",
  ],
  [
    [$oIPT->_comp('comp')],
    [],
    "_comp() no data is defined.",
  ],
  [
    [$oIPT->_comp('proto', {'proto' => "UDP"})],
    ['-p udp'],
    "_comp() proto.",
  ],
  [
    [$oIPT->_compile_ret()],
    [],
    "_compile_ret() nothing defined.",
  ],
  [
    [$oIPT->_compile_ret(undef, 'foo', 'bar')],
    [qw/foo bar/],
    "_compile_ret() no not defined.",
  ],
  [
    [$oIPT->_compile_ret([1, 0], 'foo', 'bar')],
    [qw/foo bar/],
    "_compile_ret() one not untrue.",
  ],
  [
    [$oIPT->_compile_ret([0, 0], 'foo', 'bar')],
    [qw/foo bar/],
    "_compile_ret() all not untrue.",
  ],
  [
    [$oIPT->_compile_ret([1, 1], 'foo', 'bar')],
    [qw/! foo bar/],
    "_compile_ret() all not true.",
  ],
];

test($paTests);
