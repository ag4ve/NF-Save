# NAME

NF::Save - Module for storing, parsing, and restoring iptables and 
ipset data.

# SYNOPSIS

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

    # And to get the ipset set
    print "$_\n" for ($oIPT->save());

# DESCRIPTION

NF-Save is intended to let perl import/export firewall rules and ipsets
in the exact syntax used by iptables-save / iptables-restore and ipset
save / ipset restore: same order of arguments, same way of expanding
tokens, same defaults when things weren't explicitly specified, etc.

That way, existing policies can be imported easily and completely, and
policies composed in perl code can be written out in a way that is 100%
diff-compatible with iptables-save output.

More less used methods are documented in [NF::Save::Misc](https://metacpan.org/pod/NF::Save::Misc). If you wish 
to create new modules, see [NF::Save::ModuleDoc](https://metacpan.org/pod/NF::Save::ModuleDoc).

# Common methods

## new(%Options)

%Options:

- `%UIDs` contains a hash of {'username' => #id}
- `@IPTLookup` contains replacement data to be used to handle the data 
structure (an index with an undefined value will not effect the 
original array).
- `@Flags` contains a hash of flags to be used when --syn/mss/etc would 
have been used - (arbitrary names can be defined).
- `$UseIPSET` boolean - whether or not to default lists as ipset.
- `%Policy` default policy to use.
- `$Trace` boolean - whether or not to print a stack trace with warnings.
- `$PreCheck` boolean - whether or not to pre-check the structure passed 
to rule().
- `@Modules` list of NF::Save modules to use. If this is a string, all 
modules in this namespace will be loaded.

## get($sChain, $sTable)

Return the internal data structure used to store iptables information.

## useipset($sBool)

Return whether ipset is used by default and optionally change whether
or not ipset is used by default. So:
`$ipt->useipset(1);`
is the same as:
`$ipt->new({UseIPSET => 1});`

## rule($sChain, $sRule, $sTable, $sFunc)

An interface designed to look fairly similar to the iptables CLI.

The tcp '--syn' and '! --syn' options add masks from individual from
the $rhFlags hashref.

The big difference is that the chain is seperate from the action.

- This:
`iptables -I INPUT 5 -j ACCEPT`
- Turns into this:
`$ipt->rule('INPUT', {jump => 'ACCEPT'}, undef, 'I 5');`
- The default is to APPEND to the filter table, which means the pattern is:
`$ipt->rule('INPUT', {jump => 'ACCEPT'});`
- Delete and replace have been implemented for completeness - for replace:
`$ipt->rule('OUTPUT', {jump => 'ACCEPT'}, 'filter', 'R 5');`

## get\_ipset\_data($sName)

Return internal data for an ipset or all sets if no name was given.

## save()

Return an array that can pe passed to iptables-restore. This data 
should duplicate iptables-save so that data generated with this and 
restored into iptables would show no differece when compared to the
output of:

iptables-save

## assemble(%$phParams, $sChain, $check)

Create an iptables rule for a data structure definition.
The chain name and whether to check the ruleset are optional.

# DOCUMENTATION SYNTAX

When defining the values in a hash, perl data types are used to 
describe the value type and variable names that are used to define 
the key name. Documentation may define an alternative data type not
self documented in this syntax. A hash that looks like:

{
  array   => \[qw/1 2 3/\],
  hash    => {"a" => "1", "b" => "2"},
  string  => "foo",
}

Would be defined as:

- `@array` description
- `%hash` description
- `$string` description

# TODO

- Need more tests (branch coverage is ~40%) and use cases
    - Need to handle more modules
- Integration with libiptc using FFI or similar instead of using IPC
- Make NF::RuleParser to make a NF::Save structure from iptables
- IPT allows deletion on exact rule match - not supported here

# AUTHOR

Shawn Wilson <ag4ve.us@gmail.com>

# THANKS

A special thanks to Korelogic for giving inspiration and funding for most
of this work and allowing it to be open sourced.

# COPYRIGHT

Copyright 2017 - Shawn Wilson

# LICENSE

The GNU Lesser General Public License, version 3.0 (LGPL-3.0)
http://opensource.org/licenses/LGPL-3.0
