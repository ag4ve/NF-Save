# NAME

NF::Save - Module for storing, parsing, and restoring netfilter/iptables and ipset data

# SYNOPSIS

    use NF::Save;

# DESCRIPTION

- new(%uids, @lookup, @synflags)

    `%uids` contains a hash of {'username' => #id}
    `@lookup` contains replacement data to be used to handle the data structure (an index with an undefined value will not effect the original array)
    `@synflags` contains an array of flags to be used when --syn would have been used

- get($chain, $table)

    Return the internal data structure used to store iptables information

- is\_chain($chain, $table)

    Check if a chain is defined (the filter table is assumed if none is given)

- is\_table

    Check if a table is defined

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

- raw\_rule(@rules)

    Process a full iptables rule into the data structure

# TODO

- Some tests fail (prove \-lbv t/\*\.t)
  - mist.t:
    - 10 - Assemble rule (1)
    - 13
- Need more tests and use cases
  - Need to handle more modules (and probably separate that namespace out)
  - code is kinda brittle
- Might want to look at naming in the API (->save saves a iptables rule and 
    ->ipset saves a set for ipset)

# AUTHOR

Shawn Wilson <swilson@korelogic.com>

# COPYRIGHT

Copyright 2014- Shawn Wilson

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
\# Lookup table to make sure elements are in order

# POD ERRORS

Hey! __The above document had some coding errors, which are explained below:__

- Around line 15:

    '=item' outside of any '=over'

- Around line 102:

    You forgot a '=back' before '=head1'
