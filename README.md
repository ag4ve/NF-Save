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

- new({%UIDs, @IPTLookup, @Flags})

    `%UIDs` contains a hash of {'username' => #id}
    `@IPTLookup` contains replacement data to be used to handle the data structure (an index with an undefined value will not effect the original array)
    `@Flags` contains a hash of flags to be used when --syn/mss/etc would have been used - (arbitrary names can be defined)
    `$UseIPSET` boolean - whether or not to default lists as ipset
    `%Policy` default policy to use
    `$Trace` boolean - whether or not to print a stack trace with warnings
    `$PreCheck` boolean - whether or not to pre-check the structure passed to rule().
    `@Modules` list of NF::Save modules to use. If this is a string, all modules in this namespace will be loaded.

# TODO

\- Need more tests and use cases
  - Need to handle more modules (and probably separate that namespace out)
  - code is kinda brittle
\- Integration with libiptc using FFI or similar instead of using IPC
  - Consider making a different module since the purpose of this is just to 
    dump information

# AUTHOR

Shawn Wilson <swilson@korelogic.com>

# COPYRIGHT

Copyright 2014- Shawn Wilson

# LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
\# Lookup table to make sure elements are in order

# POD ERRORS

Hey! **The above document had some coding errors, which are explained below:**

- Around line 24:

    '=item' outside of any '=over'

- Around line 35:

    You forgot a '=back' before '=head1'
