package NF::Save;

use strict;
use warnings;
use 5.010;

use Carp qw(cluck);
use Module::Load qw(load);

use subs qw(warn);

our $VERSION = '0.01';

=encoding utf8

=head1 NAME

NF::Save - Module for storing, parsing, and restoring netfilter/iptables and ipset data

=head1 SYNOPSIS

  use NF::Save;

=head1 DESCRIPTION

NF-Save is intended to let perl import/export firewall rules and ipsets
in the exact syntax used by iptables-save / iptables-restore and ipset
save / ipset restore: same order of arguments, same way of expanding
tokens, same defaults when things weren't explicitly specified, etc.

That way, existing policies can be imported easily and completely, and
policies composed in perl code can be written out in a way that is 100%
diff-compatible with iptables-save output.

=cut

my $paIPTLookup = 
[
  'src' => 'srcdst',
  'dst' => 'srcdst',
  'in' => 'io_if',
  'out' => 'io_if',
  'proto' => 'proto',
  'jump' => 'jump',
];

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

# TODO filter policies should all be ACCEPT since that is the default
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

my $phFlags = 
{
  'syn'   => 'FIN,SYN,RST,ACK SYN',
};

=over 4

=item new({%UIDs, @IPTLookup, @Flags})

C<%UIDs> contains a hash of {'username' => #id}
C<@IPTLookup> contains replacement data to be used to handle the data structure (an index with an undefined value will not effect the original array)
C<@Flags> contains a hash of flags to be used when --syn/mss/etc would have been used - (arbitrary names can be defined)
C<$UseIPSET> boolean - whether or not to default lists as ipset
C<%Policy> default policy to use
C<$Trace> boolean - whether or not to print a stack trace with warnings
C<$PreCheck> boolean - whether or not to pre-check the structure passed to rule().
C<@Modules> list of NF::Save modules to use. If this is a string, all modules in this namespace will be loaded.

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

=head1 TODO

- Need more tests and use cases
  - Need to handle more modules (and probably separate that namespace out)
  - code is kinda brittle
- Integration with libiptc using FFI or similar instead of using IPC
  - Consider making a different module since the purpose of this is just to 
    dump information

=head1 AUTHOR

Shawn Wilson E<lt>swilson@korelogic.comE<gt>

=head1 COPYRIGHT

Copyright 2014- Shawn Wilson

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
# Lookup table to make sure elements are in order

