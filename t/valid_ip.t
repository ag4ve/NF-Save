#!perl

use strict;
use warnings;

use lib 't';
use Util;

use NF::Save;

my $ipt = NF::Save->new({'testuser' => 359});

my $tests = [
  [$ipt->_valid_cidr('5.6.7.8/28'), 0, "Invalid subnet"],
  [$ipt->_valid_cidr('1.2.3.0/24'), 1, "Valid subnet"],
  [$ipt->_valid_ip('5.6.7.892'), 0, "Invalid IP"],
  [$ipt->_valid_ip('5.6.7.8/29'), 1, "Valid IP"],
  [$ipt->_valid_ip('5.6.7.8'), 1, "Valid IP no CIDR"],
  [$ipt->_cidr_ip('1.2.3.4/32'), '1.2.3.4/32', "Valid IP with mask"],
  [$ipt->_cidr_ip('1.2.3.4'), '1.2.3.4/32', "Valid IP without a mask"],
];

test($tests);
