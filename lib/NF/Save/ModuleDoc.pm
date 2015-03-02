package NF::Save::ModuleDoc;

use strict;
use warnings;
 
=encoding utf8

=head1 NAME

NF::Save::ModuleDoc - Adding a new module in this space.

=head1 SYNOPSIS

  #!/usr/bin/env/perl;

  use strict;
  use warnings;

  use NF::Save;

  my $oIPT = NF::Save->new({Modules => [qw/+core Foo/]});

  # Do work

  package NF::Save::Foo;

  use strict;
  use warning;

  my @aMixinSubs = qw/_foo/;
  
  sub Init
  {
    my ($oSelf) = @_;
  
    my $paLookup = [
      'keyword0' => '_foo',
      'keyword1' => '_foo',
    ];
    my $paPre = [qw/proto owner match list/];
    my $paPost = [qw/icmp conntrack limit comment jump/];
  
    return @aMixinSubs if ($oSelf->_add_module($paLookup, $paPre, $paPost));
  }
   
  # Return an array of TCP or UDP protocol match strings
  sub _foo
  {
    my ($oSelf, $phParams) = @_;
  
    return [$oSelf->_str_map($phParams, [
        'name lc' => "-p",
        'name lc' => "-m",
        'sport' => "--sport",
        'dport' => "--dport",
        'flags %flags' => "--tcp-flags",
      ], {
        'name' => "key"
      }, [qw/
        name
      /], {
        'flags' => $oSelf->{flags}
      }
    )];
  };

  1;

=head1 DESCRIPTION

Each module must contain an Init function that returns methods it 
presents. If the method presents a string, _add_module() should be 
used to determine where the string part should be used when creating 
the iptables rule. This is done so that a diff between an in-memory 
ruleset lines up with one generated with NF::Save.

This expands the NF::Save namespace, so be careful with the method name.
In order to use this new module, you'll need to specify a Modules hash 
with the name of your module (and possible '+core' if you want default 
modules loaded as well.

Note that the above is based off of TCP_UDP. Some names were changed 
to allow this to actually work if you were to run it (not duplicate 
namespace).

=head1 Common methods

=over 4

=item _add_module(@$paLookup, @$paPre, @$paPost)

Insert the name and method in the right place so the rule is in the order iptables
would present it.
@$paLookup is an even array of ["name" => "method"] where the method should be 
private and exclude the underscore (_) here.
@$paPre should be a list of names that should come before this module and
@$paPost should be a list of names that should come after.
If post isn't defined/found, the entry will come after the last pre entry found

=item _str_map(%$phParams, @$pamap, %$phAlt, %$phLookup)

Return a string from a definition
Input is a hashref of the input datastructure, a definition, optionally 
a third hash with alternate key map, required fields, and a lookup hash.
The definition of "map" is a balanced array of:
<key of input data structure [function]> => <value>
Or
<key of input data structure> => {<value of input data structure> => <value to use>}
The later form is used to yield different outputs depending on the input value
Lookup is a hashref of hashes whose value (string) can be substituted for the value 
of params if the key of lookup says to use it.

=back

1;

