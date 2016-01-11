#!/usr/bin/env perl 

use strict;
use warnings;

# WARNING: Data::Overlay can run code - do not process untrusted 
# configuration files

use Data::Dumper;
use YAML::XS qw(LoadFile);
use Storable qw(dclone);
use Data::Overlay;
use NF::Save;

my $sMaxLoop = 25;

my $phConfig = LoadFile($ARGV[0]);

my $oIPT = NF::Save->new({
  'Policy'  => {
    (exists($phConfig->{policy})
      ? $phConfig->{policy}
      : 'filter' => {
         'INPUT'       => 'DROP',
         'OUTPUT'      => 'DROP',
         'FORWARD'     => 'DROP',
      },
    )
  },
  UseIPSET => 0,
});
# print Dumper($phConfig);


{
  my $sSkip = 1;
  my $phTpl = $phConfig->{template};
  for (my $sCount = 0; $sCount < $sMaxLoop and $sSkip; $sCount++)
  {
    ($phTpl, $sSkip) = tpl_expand($phTpl, $phTpl);
#    print "[$sCount] [$sSkip] " . Dumper($phTpl);
  }
print "[$sSkip] " . Dumper($phTpl);

#  foreach my $sTable (keys %{$phConfig->{firewall}})
#  {
#    my $phChains = $phConfig->{firewall}{$sTable};
#    foreach my $sChain (keys %$phChains)
#    {
#      foreach my $phRule (@{$phChains->{$sChain}})
#      {
#        $oIPT->rule($sChain, $phRule);
#      }
#    }
#  }
#  foreach my $list (keys %{$phConfig->{lists}})
#  {
#    $oIPT->add_list($list, $phConfig->{lists}{$list});
#  }
#  
#  print "$_\n" for ($oIPT->save());
}

# Templates may have templates and policies may have templates
# Proc is what is being processed and Tpl are templates it uses
sub tpl_expand
{
  my ($phProc, $phTpl) = @_;

  if (not defined($phProc) or not defined($phTpl) or
    ref($phProc) ne 'HASH' or ref($phTpl) ne 'HASH')
  {
    warn "Template is not a hash.\n";
    return;
  }

  my $sSkip = 0;
  $phProc = dclone($phProc);
  while (my ($sKey, $oValue) = each %$phProc)
  {
    if (not defined($oValue))
    {
      $phProc->{$sKey} = [];
    }
    elsif (ref($oValue) eq 'HASH')
    {
      my ($sTmpSkip, $paTmp) = tpl_expand_part($oValue, $phTpl);
      $sSkip++ if ($sTmpSkip);
      $phProc->{$sKey} = $paTmp if (defined($paTmp));
    }
    elsif(ref($oValue) eq 'ARRAY')
    {
      my @aData;
      foreach my $oTmpVal (@$oValue)
      {
        next if (ref($oTmpVal) ne 'HASH');
        my ($sTmpSkip, $paTmp) = tpl_expand_part($oTmpVal, $phTpl);
        $sSkip++ if ($sTmpSkip);
        push @aData, @$paTmp if (defined($paTmp));
      }
      $phProc->{$sKey} = [@aData] if (scalar(@aData));
    }
    else
    {
      $sSkip++;
    }
  }

  return $phProc, $sSkip;
}

# Return 1 increases skip count
sub tpl_expand_part
{
  my ($oValue, $phTpl) = @_;

  # No template defined
  if (not defined($oValue->{template}))
  {
    # No template is defined - a single element array with the hash is given
    return (undef, [$oValue]);
  }
  # Handle templates - processed templates are arrays
  else
  {
    my $paTmp;
    my $oTpl = $oValue->{template};
    # A single template valuea - an array value the length of the template
    if (ref(\$oTpl) eq 'SCALAR')
    {
      if (not defined($phTpl->{$oTpl}))
      {
        warn "Template [$oTpl] not defined.\n";
        return;
      }
      # Make sure templates do not contain templates
      elsif (ref($phTpl->{$oTpl}) ne 'ARRAY')
      {
        return 1;
      }

      push @$paTmp, @{$phTpl->{$oTpl}};
    }
    # Multiple templates - an array value the length of all the templates given
    elsif (ref($oTpl) eq 'ARRAY')
    {
      # Make sure templates do not contain templates
      if (my @aTpl = grep {not defined($phTpl->{$_})} @$oTpl)
      {
        warn "Template [" . join('][', @aTpl) . "] not defined.\n";
        return;
      }
      # Make sure templates do not contain templates
      elsif (grep {ref($phTpl->{$_}) ne 'ARRAY'} @$oTpl)
      {
        return 1;
      }

      # Push all templates into one big list
      foreach my $sTpl (@$oTpl)
      {
        push @$paTmp, @{$phTpl->{$sTpl}};
      }
    }

    delete $oValue->{template};

    # Handle modifications
    # From a modify array
    if (defined($oValue->{modify}) and ref($oValue->{modify}) eq 'ARRAY')
    {
      foreach my $i (0 .. $#{$oValue->{modify}})
      {
        $paTmp->[$i] //= {};
        next if (not defined($oValue->{modify}[$i]));
        $paTmp->[$i] = overlay($paTmp->[$i], $oValue->{modify}[$i]);
      }
    }
    # From (not template) elements of the hash
    elsif (keys %$oValue)
    {
      delete $oValue->{modify};
      $paTmp = [overlay($paTmp->[0], $oValue), @{$paTmp}[1 .. $#{$paTmp}]];
    }
    return (undef, dclone($paTmp));
  }
}
