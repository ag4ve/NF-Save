#!/usr/bin/env perl
#===============================================================================
# $Id: firewall.pl,v 1.153 2015/02/25 01:11:56 swilson Exp $
#
#         FILE:  firewall.pl
#
#        USAGE:  ./firewall.pl  
#
#  DESCRIPTION:  Build iptables and/or ipset rules using shell like 
#                configuration files.
#
#      OPTIONS:  ./firewall.pl --help
# REQUIREMENTS:  iptables, iproute2 [, ipset, sysctl, modprobe]
#         BUGS:  ---
#        NOTES:  This script should be Linux distro independent.
#       AUTHOR:  Shawn Wilson <swilson@korelogic.com>
#      COMPANY:  Korelogic
#      VERSION:  1.0
#      CREATED:  02/23/13 16:05:34
#     REVISION:  Beta (known to work on Gentoo and Debian)
#===============================================================================

use strict;
use warnings;

use Data::Dumper;

use Getopt::Long;
use Pod::Usage;
Getopt::Long::Configure ("bundling");

use Cwd;
use File::Spec;
use IPC::Run qw(run);

use NF::Save;

my $cmd = $0;
my $cwd = getcwd;

# This looks bad - $in_root will be defined if we're in root's group
my $in_root = grep {$_ == 0} split ' ', $(;

# We need a three state variable from getopt:
# undef if the option was not specified
# '' if we specified the option was specified with no variable
# and a possible variable
#
# The variable should be a file and an empty string should go to stdout
my $rhOpts = {
    'iptables'  => undef,
    'ipset'     => undef,
    'sysctl'    => undef,
    'reset'     => undef,
};
GetOptions( 'infile|f=s@'   => \$rhOpts->{infile},
            'iptables|t:s'  => \$rhOpts->{iptables},
            'no-iptables|T' => \$rhOpts->{niptables},
            'ipset|s:s'     => \$rhOpts->{ipset},
            'no-ipset|S'    => \$rhOpts->{nipset},
            'sysctl|c:s'    => \$rhOpts->{sysctl},
            'execute|exe|x' => \$rhOpts->{exe},
            'write|w'       => \$rhOpts->{write},
            'reset|r:i'     => \$rhOpts->{reset},
            'force'         => \$rhOpts->{force},
            'silent'        => \$rhOpts->{silent},
            'debug|d:i'     => \$rhOpts->{debug},
            'help|h'        => \$rhOpts->{help},
        ) or pod2usage({-verbose => 0, -output => \*STDERR,
            -msg => "$0 no parameter found\n" .
                    "Use -help for options\n"
        });
if ($rhOpts->{man})
{
  pod2usage( -verbose => 2 ); 
}
elsif (defined($rhOpts->{help}))
{
  pod2usage( -verbose => 0, -output => \*STDERR,
              -msg => "$0 [options]\n");
}

# If @missing gets defined, the file does not exist
if (defined($rhOpts->{infile}) and ref($rhOpts->{infile}) eq 'ARRAY' and 
  my @missing = grep {! -f $_} @{$rhOpts->{infile}})
{
  pod2usage({-verbose => 0, -output => \*STDERR,
    -msg => "$0 Input file(s): " . join(", ", @missing) . " do not exist\n"
  });
}

# Sanity check
die "You don't have permission to run iptables and/or ipset.\n"
  if (defined($rhOpts->{exe}) and not $in_root);

# By default, work with both iptables and ipset 
# NOTE: $can_ipset is checked elsewhere
if (not defined($rhOpts->{iptables}) and 
  not defined($rhOpts->{ipset}) and 
  not defined($rhOpts->{sysctl}))
{
  $rhOpts->{iptables} = '';
  $rhOpts->{ipset} = '';
}

# Should be constant
my %exp_proto = (
  'T' => 'TCP',
  'U' => 'UDP',
  'I' => 'ICMP',
);

my %rule = (
  'in'  => 'INPUT',
  'out' => 'OUTPUT',
  'fwd' => 'FORWARD',
);

# TODO load a default policy from config and combine them

# TODO Not used
my $rhAltTables = {
  'hackerlans' => [qw/
    check_hackerlans_in
    check_hackerlans_out
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


{
  my $sSkip = 1;
  my $phTpl = $phConfig->{template};
  for (my $sCount = 0; $sCount < $sMaxLoop and $sSkip; $sCount++)
  {
    ($phTpl, $sSkip) = tpl_expand($phTpl, $phTpl);
  }

  foreach my $sTable (keys %{$phConfig->{firewall}})
  {
    my $phChains = $phConfig->{firewall}{$sTable};
    ($phChains) = tpl_expand($phChains, $phTpl);
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



