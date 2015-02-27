#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $oIPT = NF::Save->new({'UIDs' => {'testuser' => 359}}

my $paTests = 
[
  [
    $oIPT->_valid_cidr('5.6.7.8/28'), 
    0, 
    "Invalid subnet"
  ],
  [
    $oIPT->_valid_cidr('1.2.3.0/24'), 
    1, 
    "Valid subnet"
  ],
  [
    $oIPT->_valid_ip('5.6.7.892'), 
    0, 
    "Invalid IP"
  ],
  [
    $oIPT->_valid_ip('5.6.7.8/29'), 
    1, 
    "Valid IP"
  ],
  [
    $oIPT->_valid_ip('5.6.7.8'), 
    1, 
    "Valid IP no CIDR"
  ],
  [
    $oIPT->_cidr_ip('1.2.3.4/32'), 
    '1.2.3.4/32', 
    "Valid IP with mask"
  ],
  [
    $oIPT->_cidr_ip('1.2.3.4'), 
    '1.2.3.4/32', 
    "Valid IP without a mask"
  ],
];

test($paTests);
