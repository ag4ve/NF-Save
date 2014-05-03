# NAME

NF::Save - Module for storing, parsing, and restoring netfilter/iptables and ipset data

# SYNOPSIS

    use NF::Save;

# DESCRIPTION

NF-Save is intended to let perl import/export firewall rules and ipsets
in the exact syntax used by iptables-save / iptables-restore and ipset
save / ipset restore: same order of arguments, same way of expanding
tokens, same defaults when things weren't explicitly specified, etc.

That way, existing policies can be imported easily and completely, and
policies composed in perl code can be written out in a way that is 100%
diff-compatible with iptables-save output.

- new({%uids, @IPTLookup, @SynFlags})

    `%uids` contains a hash of {'username' => #id}
    `@IPTLookup` contains replacement data to be used to handle the data structure (an index with an undefined value will not effect the original array)
    `@SynFlags` contains an array of flags to be used when --syn would have been used
    `$useipset` boolean - whether or not to default lists as ipset
    `%Policy` default policy to use

- get($chain, $table)

    Return the internal data structure used to store iptables information

- is\_chain($chain, $table)

    Check if a chain is defined (the filter table is assumed if none is given)

- is\_table

    Check if a table is defined

- useipset($bool)

    Change whether ipset is used bu default.

- get\_policy($chain, $table)

    Get the policy for a chain

- get\_header($chain, $table)

    Get header policies for iptable-save

- ipset($name, @list, $opts)

    Define an ipset list.

    `$name` is the name of the set
    `@list` is a list of addresses in the set
    `%opts` parameters for the set

- get\_set($name)

    Return an array of data appropriate for 'ipset restore'. Return only one set if a valid name was supplied or all sets if no set name was given.

- is\_ipset($name)

    Check if an ipset exists

- get\_ipset\_data($name)

    Return internal data for an ipset or all sets if no name was given

- save()

    Return an array that can pe passed to iptables-restore. This data should duplicate iptables-save so that data generated with this and restored into iptables would show no differece when compared to iptables-save output

- get\_tables()

    Return a list of tables

- save\_table($table)

    Return an iptables-save array for all chains in a table (default to filter if no table is supplied)

- get\_chain($table)

    Return a list of chains for a table

- save\_chain($chain, $table)

    Return an array with iptables-save data for one chain

- get\_rules($chain, $table)

    Return data structure of rules in a chain

- assemble(%params)

    Put an iptables rule for a data structure definition

- rule($chain, $rule, $table, $func)

    An interface designed to look fairly similar to the iptables cli

    The tcp '--syn' and '! --syn' options add masks from individual from
    the $raSynFlags arrayref

    The big difference is that the chain is seperate from the action
    This:
    `iptables -I INPUT 5 -j ACCEPT`
    Turns into this:
    `ipt('INPUT', '-j ACCEPT', undef, 'I 5');`
    The default is to append to the filter table, which means the pattern is:
    `ipt('INPUT', '-j ACCEPT');`
    Delete and replace have been implemented for completeness - for replace:
    `ipt('OUTPUT', -j ACCEPT', 'filter', 'R 5');`

- is\_user($username)

    Return true if user has been defined.

- comment($str, $where)

    Add a comment that will be displayed in iptables/ipset output

- raw\_rule(@rules)

    Process a full iptables rule into the data structure

# TODO

\- Some tests fail (prove -lbv t/\*.t)
  - mist.t:
    - 10 - Assemble rule (1)
    - 13
\- Need more tests and use cases
  - Need to handle more modules (and probably separate that namespace out)
  - code is kinda brittle
\- Might want to look at naming in the API (->save saves a iptables rule and 
    ->ipset saves a set for ipset)

# AUTHOR

Shawn Wilson <swilson@korelogic.com>

# COPYRIGHT

Copyright 2014- Shawn Wilson

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
\# Lookup table to make sure elements are in order
