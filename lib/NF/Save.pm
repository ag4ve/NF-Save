package NF::Save;

use strict;
use warnings;
use 5.010;

use Carp qw(cluck);
use Module::Load qw(load);

use subs qw(warn);

our $VERSION = '0.02';

=encoding utf8

=head1 NAME

NF::Save - Module for storing, parsing, and restoring iptables and 
ipset data.

=head1 SYNOPSIS

  use NF::Save;

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
      }
    }
  );

  my $paStruct = 
  [
    {
      'in' => "eth0",
      'udp' => 
      {
        'sport' => "1024:65535",
        'dport' => "53",
      }, 
      'dst' => "192.168.15.1",
      'comment' => [qw/nameserver/],
      'jump' => "ACCEPT",
    },
    {
      # more rules
    },
  ];

  # Add rules to the OUTPUT chain.
  foreach my $phRule (@$paStruct)
  {
    $oIPT->rule('OUTPUT', $phRule);
  }

  # Get a set of rules that could be used with: 
  # $ ./firewall.pl | iptables-restore
  print "$_\n" for ($oIPT->save());

=head1 DESCRIPTION

NF-Save is intended to let perl import/export firewall rules and ipsets
in the exact syntax used by iptables-save / iptables-restore and ipset
save / ipset restore: same order of arguments, same way of expanding
tokens, same defaults when things weren't explicitly specified, etc.

That way, existing policies can be imported easily and completely, and
policies composed in perl code can be written out in a way that is 100%
diff-compatible with iptables-save output.

More less used methods are documented in L<NF::Save::Misc>. If you wish 
to create new modules, see L<NF::Save::ModuleDoc>.

=cut

# Lookup table to make sure elements are in order
my $paIPTLookup = 
[
  'src' => 'srcdst',
  'dst' => 'srcdst',
  'in' => 'io_if',
  'out' => 'io_if',
  'proto' => 'proto',
  'jump' => 'jump',
];

# Core iptables modules to load if +core is defined or if nothing else is defined
my $phModules =
{
  'core' => [qw/
    Comment
    Limit
    Conntrack
    ICMP
    TCP_UDP
    ListSet
    Match
    Owner
  /],
};

# Policy map for standard table chains
my $phPolicy = 
{
  'filter'  => 
  {
    'INPUT'       => 'ACCEPT',
    'OUTPUT'      => 'ACCEPT',
    'FORWARD'     => 'ACCEPT',
  },
  'mangle'  => 
  {
    'PREROUTING'  => 'ACCEPT',
    'INPUT'       => 'ACCEPT',
    'FORWARD'     => 'ACCEPT',
    'OUTPUT'      => 'ACCEPT',
    'POSTROUTING' => 'ACCEPT',
  },
  'nat'     => 
  {
    'PREROUTING'  => 'ACCEPT',
    'INPUT'       => 'ACCEPT',
    'OUTPUT'      => 'ACCEPT',
    'POSTROUTING' => 'ACCEPT',
  },
  'raw'     => 
  {
    'OUTPUT'      => 'ACCEPT',
    'POSTROUTING' => 'ACCEPT',
    'PREROUTING'  => 'ACCEPT',
  },
};

# actual flags to use for shorthand
my $phFlags = 
{
  'syn'   => 'FIN,SYN,RST,ACK SYN',
};

=head1 Common methods

=over 4

=item new({%UIDs, @IPTLookup, @Flags})

C<%UIDs> contains a hash of {'username' => #id}
C<@IPTLookup> contains replacement data to be used to handle the data 
structure (an index with an undefined value will not effect the 
original array)
C<@Flags> contains a hash of flags to be used when --syn/mss/etc would 
have been used - (arbitrary names can be defined)
C<$UseIPSET> boolean - whether or not to default lists as ipset
C<%Policy> default policy to use
C<$Trace> boolean - whether or not to print a stack trace with warnings
C<$PreCheck> boolean - whether or not to pre-check the structure passed 
to rule().
C<@Modules> list of NF::Save modules to use. If this is a string, all 
modules in this namespace will be loaded.

=cut

sub new
{
  my ($oClass, $phParams) = @_;

  if (exists($phParams->{Trace}) and $phParams->{Trace} == 1)
  {
    *warn = \&cluck;
  }
  else
  {
    *warn = sub { &CORE::warn };
  }

  my $phUseParams = 
  {
    'nf' => 
    {
      'filter' => 
      {
        'INPUT' => [],
        'OUTPUT' => [],
        'FORWARD' => [],
      },
    },
    'set' => {},
    'nf comment' => [],
    'set comment' => [],
  };
  $phUseParams->{uids} = 
  (
    (exists($phParams->{UIDs}) and ref($phParams->{UIDs}) eq 'HASH') ?
    $phParams->{UIDs} : {}
  );

  if (exists($phParams->{IPTLookup}) and ref($phParams->{IPTLookup}) eq 'ARRAY' and
    scalar($phParams->{IPTLookup}) > 0)
  {
    for my $i (@{$phParams->{IPTLookup}})
    {
      $paIPTLookup->[$i] = $phParams->{IPTLookup}[$i]
        if (scalar($phParams->{IPTLookup}[$i]));
    }
  }
  $phUseParams->{lookup} = $paIPTLookup;

  # Overright default
  $phParams->{Policy} //= {};
  $phUseParams->{Policy} = {%$phPolicy, %{$phParams->{Policy}}};

  $phUseParams->{flags} = (
    (exists($phParams->{Flags}) and ref($phParams->{Flags}) eq 'ARRAY') ?
    $phParams->{flags} : $phFlags
  );

  $phUseParams->{useipset} = $phParams->{UseIPSET} // 0;

  $phUseParams->{precheck} = $phParams->{PreCheck} // 0;

  my $oSelf = bless $phUseParams, $oClass;

  my @aModules;
  if (exists($phParams->{Modules}) and ref($phParams->{Modules}) eq 'ARRAY')
  {
    foreach my $sModule (@{$phParams->{Modules}})
    {
      if ($sModule =~ /^\+(.+)$/)
      {
        push @aModules, @{$phModules->{$1}}
          if (exists($phModules->{$1}) and ref($phModules->{$1}) eq 'ARRAY');
      }
      else
      {
        push @aModules, $sModule;
      }
    }
  }
  else
  {
    push @aModules, @{$phModules->{core}};
  }

  foreach my $sModule ('Helper', 'Misc', @aModules)
  {
    my $sFullName = "NF::Save::" . $sModule;
    load $sFullName;
    {
      my $sInitFunc = $sFullName->can('Init');
      no strict 'refs';
      if (not $sInitFunc)
      {
        warn "$sInitFunc does not exist - skipping\n";
        next;
      }
      my @aSubs = $sInitFunc->($oSelf);
      foreach my $sSub (@aSubs)
      {
        my $sFullSub = $sFullName . "::" . $sSub;
        if (not exists(&{$sFullSub}))
        {
          warn "No function [$sFullSub]\n";
          next;
        }
        warn "Namespace conflict [$sFullSub]\n" if ($oSelf->can($sSub));
        *{"NF::Save::" . $sSub} = *{$sFullSub};
      }
    }
  }

  return $oSelf;
}


1;

__END__

=item get($sChain, $sTable)

Return the internal data structure used to store iptables information

=item useipset($sBool)

Change whether ipset is used by default.

=item rule($sChain, $sRule, $sTable, $sFunc)

An interface designed to look fairly similar to the iptables cli

The tcp '--syn' and '! --syn' options add masks from individual from
the $rhFlags hashref

The big difference is that the chain is seperate from the action
This:
C<iptables -I INPUT 5 -j ACCEPT>
Turns into this:
C<$ipt->rule('INPUT', {jump => 'ACCEPT'}, undef, 'I 5');>
The default is to APPEND to the filter table, which means the pattern is:
C<$ipt->rule('INPUT', {jump => 'ACCEPT'});>
Delete and replace have been implemented for completeness - for replace:
C<$ipt->rule('OUTPUT', {jump => 'ACCEPT'}, 'filter', 'R 5');>

=item get_ipset_data($sName)

Return internal data for an ipset or all sets if no name was given

=item save()

Return an array that can pe passed to iptables-restore. This data 
should duplicate iptables-save so that data generated with this and 
restored into iptables would show no differece when compared to 
iptables-save output

=item assemble(%$phParams, $sChain, $check)

Create an iptables rule for a data structure definition.
The chain name and whether to check the ruleset are optional.

=back

=head1 TODO

- dist.ini should use Module::Build::Tiny 0.034 so that a local install with 
  Debian packages can succeed.
- Need more tests and use cases
  - Need to handle more modules (and probably separate that namespace out)
  - code is kinda brittle
- Integration with libiptc using FFI or similar instead of using IPC
  - Consider making a different module since the purpose of this is just to 
    dump information
- IPT allows deletion on exact rule match - not supported here

=head1 AUTHOR

Shawn Wilson E<lt>swilson@korelogic.comE<gt>

=head1 COPYRIGHT

Copyright 2014- Shawn Wilson

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

