#!/usr/bin/env perl 

use strict;
use warnings;

use Data::Dumper;
use YAML::XS 'LoadFile';
use NF::Save;

my $phConfig = LoadFile($ARGV[0]);

my $oIPT = NF::Save->new(
  {
    'Policy'  =>
    {
      'filter'    =>
      {
        'INPUT'       => 'DROP',
        'OUTPUT'      => 'DROP',
        'FORWARD'     => 'DROP',
      },
    },
    UseIPSET => 0,
  }
);

foreach my $sTable (keys %{$phConfig->{firewall}})
{
  my $phChains = $phConfig->{firewall}{$sTable};
  foreach my $sChain (keys %$phChains)
  {
    foreach my $phRule (@{$phChains->{$sChain}})
    {
      $oIPT->rule($sChain, $phRule);
    }
  }
}
foreach my $list (keys %{$phConfig->{lists}})
{
  $oIPT->add_list($list, $phConfig->{lists}{$list});
}

print "$_\n" for ($oIPT->save());
