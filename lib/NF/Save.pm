package NF::Save;

use strict;
use warnings;
use 5.010;

our $VERSION = '0.01';

use Socket;

=head1 NAME

NF::Save - Module for storing, parsing, and restoring netfilter/iptables and ipset data

=head1 SYNOPSIS

  use NF::Save;

=head1 DESCRIPTION

Milla::BP is

=cut

my $raIPTLookup = [
  'src' => 'srcdst',
  'dst' => 'srcdst',
  'in' => 'io_if',
  'out' => 'io_if',
  'proto' => 'proto',
  'owner' => 'owner',
  'match' => 'match',
  'list set' => 'list_set',
  'tcp' => 'tcp_udp',
  'udp' => 'tcp_udp',
  'icmp' => 'icmp',
  'conntrack' => 'ct',
  'limit' => 'limit',
  'comment' => 'comment',
  'jump' => 'jump',
];

# TODO implement this
# What --syn get expanded into - not implemented yet
my $raSynFlags = [
  'FIN,SYN,RST,ACK SYN',
];

=item new(%uids, @lookup, @synflags)

C<%uids> contains a hash of {'username' => #id}
C<@lookup> contains replacement data to be used to handle the data structure (an index with an undefined value will not effect the original array)
C<@synflags> contains an array of flags to be used when --syn would have been used

=cut

sub new
{
  my ($class, $uids, $IPTLookup, $SynFlags) = @_;

  $uids = (defined($uids) and ref($uids) eq 'HASH' ? $uids : {});

  if (defined($IPTLookup) and ref($IPTLookup) eq 'ARRAY' and
    scalar($IPTLookup) > 0)
  {
    for my $i (@$IPTLookup)
    {
      $raIPTLookup->[$i] = $IPTLookup->[$i]
        if (scalar($IPTLookup->[$i]));
    }
  }

  $raSynFlags = $SynFlags // $raSynFlags;

  my $self = bless {
    'nf' => {},
    'set' => {},
    'uids' => $uids,
    'lookup' => $raIPTLookup,
    'synflags' => $raSynFlags,
  }, $class;

  return $self;
}

=item get($chain, $table)

Return the internal data structure used to store iptables information

=cut

sub get
{
  my ($self, $chain, $table) = @_;
  $table //= 'filter';

  if (not $self->is_table($table) or not defined($chain))
  {
    return $self->{nf};
  }
  elsif (not defined($chain) or not $self->is_chain($chain, $table))
  {
    return $self->{nf}{$table};
  }
  else
  {
    return $self->{nf}{$table}{$chain};
  }
}

=item is_chain($chain, $table)

Check if a chain is defined (the filter table is assumed if none is given)

=cut

sub is_chain
{
  my ($self, $chain, $table) = @_;
  $table //= 'filter';

  return (($self->is_table($table) and exists($self->{nf}{$table}{$chain})) ? 1 : 0);
}

=item is_table

Check if a table is defined

=cut

sub is_table
{
  my ($self, $table) = @_;

  return (exists($self->{nf}{$table}) ? 1 : 0);
}

=item ipset($name, @list, $opts)

Define an ipset list.

C<$name> is the name of the set
C<@list> is a list of addresses in the set
C<%opts> parameters for the set

=cut

# TODO only hash:net is assumed in the list - other types should be allowed and looked for
sub ipset
{
  my ($self, $name, $list, $opts) = @_;

  return undef unless (defined($name) and 
    defined($list) and ref($list) eq 'ARRAY');

  my $aIPs;
  @$aIPs = grep {defined($_)} map {$self->_cidr_ip($_)} @$list;

  my $return = (scalar(@$list) - scalar(@$aIPs));

  if (not $self->is_ipset($name))
  {
    $self->{ipset}{$name} = {'list' => $aIPs};
  }
  else
  {
    push @{$self->{ipset}{$name}{list}}, @$aIPs;
  }

  if (defined($opts) and ref($opts) eq 'HASH')
  {
    foreach my $key (keys %$opts)
    {
      $self->{ipset}{$name}{$key} = $opts->{$key};
    }
  }

  return ($return ? -$return : 1);
}

=item get_set($name)

Return an array of data appropriate for 'ipset restore'. Return only one set if a valid name was supplied or all sets if no set name was given.

=cut

sub get_ipset
{
  my ($self, $name) = @_;

  return undef if (defined($name) and not $self->is_ipset($name));
  my @iter = ($name // keys(%{$self->{ipset}}));

  my @return;
  foreach my $name (@iter)
  {
    my $data = $self->{ipset}{$name};
    my $type = $data->{type} // 'hash:net';
    my $family = $data->{family} // 'inet';
    my $hashsize = $data->{hashsize} // 1024;
    my $maxelen = $data->{maxelen} // 65536;

    push @return, "create $name $type family $family hashsize $hashsize maxelen $maxelen";
    push @return, map {"add $name $_"} @{$data->{list}};
  }

  return [@return];
}

=item is_ipset($name)

Check if an ipset exists

=cut

sub is_ipset
{
  my ($self, $name) = @_;

  return (exists($self->{ipset}{$name}) ? 1 : 0);
}

=item get_ipset_data($name)

Return internal data for an ipset or all sets if no name was given

=cut

sub get_ipset_data
{
  my ($self, $name) = @_;

  if (not defined($name))
  {
    return $self->{ipset};
  }
  elsif ($self->is_ipset($name))
  {
    return $self->{ipset}{$name};
  }
  else
  {
    return undef;
  }
}

=item save()

Return an array that can pe passed to iptables-restore. This data should duplicate iptables-save so that data generated with this and restored into iptables would show no differece when compared to iptables-save output

=cut

sub save
{
  my ($self) = @_;

  my @return;

  foreach my $table ($self->get_tables())
  {
    push @return, @{$self->save_table($table)};
  }
  return @return;
}

=item get_tables()

Return a list of tables

=cut

sub get_tables
{
  my ($self) = @_;

  return (keys %{$self->{nf}});
}

=item save_table($table)

Return an iptables-save array for all chains in a table (default to filter if no table is supplied)

=cut

sub save_table
{
  my ($self, $table) = @_;
  $table //= 'filter';

  return undef if (not $self->is_table($table));

  my @return;
  foreach my $chain ($self->get_chains($table))
  {
    push @return, @{$self->save_chain($chain, $table)};
  }

  return @return;
}

=item get_chain($table)

Return a list of chains for a table

=cut

sub get_chains
{
  my ($self, $table) = @_;

  return undef if (not $self->is_table($table));
  return (keys %{$self->{nf}{$table}});
}

=item save_chain($chain, $table)

Return an array with iptables-save data for one chain

=cut

sub save_chain
{
  my ($self, $chain, $table) = @_;
  $table //= 'filter';

  return if (not defined($chain) and not $self->is_chain($chain, $table));

  my @return;
  foreach my $rule ($self->get_rules($chain, $table))
  {
    my @assembled = $self->assemble($rule);
    return if (not scalar(@assembled));
    push @return, "-A $chain " . join(" ", map {@$_} @{$self->_expand(@assembled)});
  }

  return [@return];
}

=item get_rules($chain, $table)

Return data structure of rules in a chain

=cut

sub get_rules
{
  my ($self, $chain, $table) = @_;
  $table //= 'filter';

  return undef if (not $self->is_chain($chain, $table));
  return @{$self->{nf}{$table}{$chain}};
}

=item assemble(%params)

Put an iptables rule for a data structure definition

=cut

sub assemble
{
  my ($self, $hParams) = @_;

  my @iptparts;
  $self->_each_kv($self->{lookup});
  my $splitkey = [
    map {[split(' ', $_)]}
      $self->_each_kv('keys', 'lookup')
  ];

  while (my ($listkey, $comp) = $self->_each_kv())
  {
    $comp = '_' . $comp;

    my @key = grep {/^!?$listkey$/i} keys %$hParams;
    if (scalar(@key) > 1)
    {
      warn "Multiple keys with similar names [" . 
        join("] [", @key) . "] - Moving on\n";
      next;
    }
    elsif (scalar(@key) == 0)
    {
      next;
    }

    if (not $self->can($comp))
    {
      warn "No method [$comp] - skipping\n";
      next;
    }

    my $pval = $hParams->{$key[0]};

    my $data;
    if (ref(\$pval) eq 'SCALAR')
    {
      $data = {'name' => $pval};
    }
    elsif (ref($pval) eq 'ARRAY')
    {
      $data = {'name' => join(' ', @$pval)};
    }
    elsif (ref($pval) eq 'HASH')
    {
      $data = $pval;
    }
    $data->{key} = $key[0] if (not defined($data->{key}));

    my $ret = $self->$comp($data);

    if (defined($ret) and ref($ret) eq 'ARRAY')
    {
      push @iptparts, $ret;
    }
    else
    {
      warn "No data or invalid data type returned.\n";
    }
  }

  return [@iptparts];
}

=item rule($chain, $rule, $table, $func)

An interface designed to look fairly similar to the iptables cli

The tcp '--syn' and '! --syn' options add masks from individual from
the $raSynFlags arrayref

The big difference is that the chain is seperate from the action
This:
C<iptables -I INPUT 5 -j ACCEPT>
Turns into this:
C<ipt('INPUT', '-j ACCEPT', undef, 'I 5');>
The default is to append to the filter table, which means the pattern is:
C<ipt('INPUT', '-j ACCEPT');>
Delete and replace have been implemented for completeness - for replace:
C<ipt('OUTPUT', -j ACCEPT', 'filter', 'R 5');>

=cut

sub rule
{
  my ($self, $chain, $rule, $table, $func) = @_;

  $table //= 'filter';
  $func //= 'A';
  my $do;
  $do = uc(substr($1, 0, 1))
    if ($func =~ /^(I(NSERT)?|A(PPEND)?|D(ELETE)?|R(EPLACE)?)\b/i);

  return if (not defined($do));

  my $num = (($func =~ /\S+ ([0-9]+)/) ? $1 : '1');

  # Filter syn mask
  if (exists($rule->{proto}) and ref($rule->{proto}) eq 'ARRAY')
  {
    push @{$rule->{proto}}, $self->{synflags};
  }

  $self->{nf}{$table} = {} unless (ref($self->{nf}{$table}) eq 'HASH');
  $self->{nf}{$table}{$chain} = () unless (ref($self->{nf}{$table}{$chain}) eq 'ARRAY');

  return $self->_ipt_do($rule, $table, $chain, $do, $num);
}

# Actually write the rule from ipt
# NOTE This should be a private function
sub _ipt_do
{
  my ($self, $rule, $table, $chain, $do, $num) = @_;

  $num = $num -1 if ($num eq $num+0);

  my $ret;
  if ($do eq 'A')
  {
    $ret = 1 unless splice
      @{$self->{nf}{$table}{$chain}},
      scalar(@{$self->{nf}{$table}{$chain}}) - $num,
      0,
      $rule;
  }
  elsif ($do eq 'I')
  {
    $ret = 1 unless splice
      @{$self->{nf}{$table}{$chain}},
      $num,
      0,
      $rule;
  }
  elsif ($do eq 'D')
  {
    $ret = splice
      @{$self->{nf}{$table}{$chain}},
      $num,
      1;
  }
  elsif ($do eq 'R')
  {
    $ret = splice
      @{$self->{nf}{$table}{$chain}},
      $num,
      1,
      $rule;
  }

  return $ret;
}

=item raw_rule(@rules)

Process a full iptables rule into the data structure

=cut

sub raw_rule
{
  my ($self, $rules) = @_;

  return unless (defined($rules) and ref($rules) eq 'ARRAY');

  my $return;
  foreach my $rule (@{$rules})
  {
    my $orig_rule = $rule;

    my $table;
    {
      $rule =~ s/^-t *([^ ]+) //;
      $table = $1 // 'filter';
    }

    my $chain;
    {
      $rule =~ s/^-A *([^ ]+) //;
      $chain = $1;
    }

    my ($nsrc, $src);
    {
      $rule =~ s/^(!)? -s *([0-9\.]+) //;
      $nsrc = $1;
      $src = $2;
    }

    my ($ndst, $dst);
    {
      $rule =~ s/^(!)? -d *([0-9\.]+) //;
      $ndst = $1;
      $dst = $2;
    }

    my $mproto;
    {
      $rule =~ s/^-m (tcp|TCP|udp|UDP|icmp|ICMP) //;
      $mproto = $1;
    }
      
    my ($sport, $dport, $flags, $type);
    if ($mproto =~ /tcp|udp/i)
    {
      {
        $rule =~ s/^(?:--sport ([0-9:]+) )?(?:--dport ([0-9:]+) )?//;
        $sport = $1;
        $dport = $2;
      }
      $rule =~ s/^ // if (defined($sport) or defined($dport));

      if ($mproto =~ /tcp/i)
      {
        $rule =~ s/^--tcp-flags ([^ ]+) //;
        $flags = $1;
      }
    }
    elsif ($mproto =~ /icmp/i)
    {
      $rule =~ s/^--icmp-type ([0-9]+) //;
      $type = $1;
    }

    my $owner;
    {
      $rule =~ s/^-m owner --uid-owner ([^ ]+) //;
      $owner = $1;
    }

    my ($set, $setdir);
    {
      $rule =~ s/^-m set --match-set ([^ ]+) ([^ ]+) //;
      $set = $1;
      $setdir = $2;
    }

    my $ct;
    {
      $rule =~ s/^-m conntrack --ctstate ((?:(?:NEW|RELATED|ESTABLISHED|INVALID),?)+) //;
      $ct = $1;
    }

    my ($limit, $burst);
    {
      $rule =~ s/^-m limit (?:--limit ([^ ]+) )?(?:--limit-burst ([^ ]+) )?//;
      $limit = $1;
      $burst = $2;
    }

    my $comment;
    {
      $rule =~ s/^-m comment "([^"]+)" //;
      $comment = $1;
    }

    # TODO certain jumps can hava parameters
    # TODO can '-m tcp -m udp -m icmp' be used in one rule
    my $jump;
    {
      $rule =~ s/^-j ([^ ]+)//;
      $jump = $1;
    }
    push @{$return->{$chain}{$table}}, {
      'src' => {
        'name' => $src,
        "not" => $nsrc,
      },
      'dst' => {
        'name' => $dst,
        'not' => $ndst,
      },
      'proto' => $mproto,
      lc($mproto) => {
        'name' => $mproto,
        'sport' => ($mproto !~ /icmp/i ? $sport : undef),
        'dport' => ($mproto !~ /icmp/i ? $dport : undef),
        'flags' => ($mproto =~ /(udp|tcp)/i ? $flags : undef),
        'type' => ($mproto =~ /icmp/i ? $type : undef),
      },
      'owner' => $owner,
      'set' => {
        'name' => $set,
        'direction' => $setdir,
        'useipset' => (defined($set) ? 1 : 0),
      },
      'conntrack' => $ct,
      'limit' => {
        'limit' => $limit,
        'burst' => $burst,
      },
      'comment' => $comment,
      'jump' => $jump,
    }
  }
}

# Return an array of source or destination IP address strings
sub _srcdst
{
  my ($self, $hParams) = @_;

  return [$self->_str_map($hParams, [
      'direction' => {
        'src' => "-s",
        'dst' => "-d",
      },
      'ip ip' => "",
    ], {
      'ip' => "name",
      'direction' => 'key',
    }, [qw/direction ip/],
  )];
}

# Return an array of input/output interface strings
sub _io_if
{
  my ($self, $hParams) = @_;

  if (not defined($hParams->{direction}) or not defined($hParams->{if}))
  {
    warn "No direction or interface defined - nothing done";
    return undef;
  }

  return [$self->_str_map($hParams, [
      'direction' => {
        'in' => "-i",
        'out' => "-o",
      },
      'if' => "",
    ], {
      'if' => "name",
      'direction' => "key",
    }, [qw/direction if/],
  )];
}

# Return an array of protocol strings
sub _proto
{
  my ($self, $hParams) = @_;

  return [$self->_str_map($hParams, [
      'proto lc' => "-p",
    ], {
      'proto' => "name",
    }
  )];
}

# Return an array of owner strings
sub _owner
{
  my ($self, $hParams) = @_;

  my $uid = $hParams->{name};
  if ($uid =~ /[a-z]+/i)
  {
    if (exists($self->{uids}{$uid}))
    {
      $uid = $self->{uids}{$uid};
    }
    else
    {
      warn "User not found. Passing [$uid] along.";
    }
  }

  return "-m owner" . (defined($uid) ? " --uid-owner $uid" : "");
}

# Return an array of IP address match strings or a set name
sub _list_set
{
  my ($self, $hParams) = @_;

  my $name = $hParams->{name};
  return if (not exists($self->{ipset}{$name}{list}) and
    ref($self->{ipset}{$name}{list}) ne 'ARRAY');
  my @return;

  my %hDirection;
  if (ref(\$hParams->{direction}) eq 'SCALAR')
  {
    %hDirection = map {$_ => 1} split(" ", $hParams->{direction});
  }
  elsif (ref($hParams->{direction}) eq 'ARRAY')
  {
    %hDirection = map {$_ => 1} @{$hParams->{direction}};
  }
  else
  {
    warn "Direction not defined - applying filter in both directions";
    %hDirection = (
      'src' => 1,
      'dst' => 1,
    );
  }

  if ($hParams->{useipset})
  {
    warn "Set [$name] has not been defined\n" unless ($self->is_ipset($name));
    push @return, "-m set --match-set $name " . join(",", sort {$b cmp $a} keys(%hDirection));
  }
  else
  {
    my @list = @{$self->{ipset}{$name}{list}}; 
    if (exists($hDirection{src}))
    {
      push @return, map {"-s $_"} @list;
    }
    if (exists($hDirection{dst}))
    {
      push @return, map {"-d $_"} @list;
    }
  }

  return [@return];
}

# Return an array of match strings
sub _match
{
  my ($self, $hParams) = @_;

  return [$self->_str_map($hParams, [
    'name lc' => "-m",
  ])];
}

# Return an array of TCP or UDP protocol match strings
sub _tcp_udp
{
  my ($self, $hParams) = @_;

  return [$self->_str_map($hParams, [
      'name lc' => "-p",
      'name lc' => "-m",
      'sport' => "--sport",
      'dport' => "--dport",
      'flags' => "--tcp-flags",
    ], {
      'name' => "key"
    }, [qw/name/],
  )];
}

# Return an array of ICMP protocol match strings
sub _icmp
{
  my ($self, $hParams) = @_;

  return [$self->_str_map($hParams, [
      'name lc' => "-p",
      'name lc' => "-m",
      'type' => '--icmp-type',
    ], undef, [qw/name/],
  )];
}

# Return an array of conntrack strings
sub _ct
{
  my ($self, $hParams) = @_;
  my @order = qw/NEW RELATED ESTABLISHED INVALID/;

  my @ctstate;
  if (ref($hParams->{name}) eq 'ARRAY')
  {
    @ctstate = @{$hParams->{name}};
  }
  elsif (ref(\$hParams->{name}) eq 'SCALAR')
  {
    @ctstate = split(' ', $hParams->{name});
  }

  my @str;
  push @str, "-m conntrack";
  (push @str, "--ctstate " . join(',', 
    map {
      my $unit = $_;
      grep {$unit eq $_} map {uc($_)} @ctstate;
    } @order))
    if (scalar(@ctstate));
  return [join(" ", @str)];
}

# Return an array of limit strings
sub _limit
{
  my ($self, $hParams) = @_;
  my @str;
  push @str, "-m limit";
  (push @str, "--limit " . $hParams->{limit}) 
    if ($hParams->{limit} and 
      $hParams->{limit} =~ /^[0-9]+\/(sec(ond)?|min(ute)?|hour|day)/);
  (push @str, "--limit-burst " . $hParams->{burst}) if($hParams->{burst});
  return [join(" ", @str)];
}

# Return an array of comment strings
sub _comment
{
  my ($self, $hParams) = @_;

  my @parts;
  if (ref($hParams->{name}) eq 'ARRAY' and scalar(@{$hParams->{name}}))
  {
    push @parts, @{$hParams->{name}};
  }
  elsif (ref(\$hParams->{name}) eq 'SCALAR' and length($hParams->{name}))
  {
    push @parts, $hParams->{name};
  }
  else
  {
    return undef;
  }

  return ["-m comment --comment \"" . join(" ", grep {defined($_)} @parts) . "\""];
}

# Return an array of jump strings
sub _jump
{
  my ($self, $hParams) = @_;
  return if (not defined($hParams->{name}));
  my $jump = $hParams->{name};
  warn "Assuming wrong case for [$jump] - matching against [" . uc($jump) . "]\n"
    if ($jump =~ /[a-z]/ and $jump =~ /^(LOG|REJECT|CT|SNAT|DNAT)$/i);

  if (uc($jump) eq 'LOG')
  {
    return [$self->_str_map($hParams, [
        'name uc' => "-j",
        'prefix qq' => "--log-prefix",
        'tcp bool' => "--log-tcp-options",
        'ip bool' => "--log-ip-options",
        'uid bool' => "--log-uid",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($jump) eq 'REJECT')
  {
    return [$self->_str_map($hParams, [
        'name uc' => "-j",
        'with bool' => "--reject-with icmp-port-unreachable",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($jump) eq 'CT')
  {
    return [$self->_str_map($hParams, [
        'name uc' => "-j",
        'notrack bool' => "--notrack",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($jump) eq 'SNAT')
  {
    return [$self->_str_map($hParams, [
        'name uc' => "-j",
        'src ip' => "--to-source",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($jump) eq 'DNAT')
  {
    return [$self->_str_map($hParams, [
        'name uc' => "-j",
        'dst ip' => "--to-destination",
      ], undef, [qw/name/],
    )];
  }
  else
  {
    return [$self->_str_map($hParams, [
        'name' => "-j",
      ], undef, [qw/name/]
    )];
  }
}

# Return a string from a definition
# Input is a hashref of the input datastructure, a definition, optionally 
# a third hash with alternate keys to try, and required fields.
# The definition is a balanced array of:
# <key of input data structure [function]> => <value>
# Or
# <key of input data structure> => {<value of input data structure> => <value to use>}
# The later form is used to yield different outputs depending on the input value
sub _str_map
{
  my ($self, $hParams, $map, $alt, $require) = @_;

  my %hRequire = map {$_ => 0} @$require;

  my (@ret, @done);
  $self->_each_kv($map, 'str_map');
  while (my ($mapkey, $mapval) = $self->_each_kv(undef, 'str_map'))
  {
    my ($testkey) = $mapkey =~ /^([^ ]+)/;
    my @PossibleKeys;
    push @PossibleKeys, $testkey if (defined($testkey) and length($testkey));
    push @PossibleKeys, $alt->{$testkey} 
      if (defined($alt) and ref($alt) eq 'HASH' and defined($alt->{$testkey}));
    # mapped string and function. Eg 'name' and 'lc'
    my ($mapstr, undef, $mapfunc) = $mapkey =~ /^([^ ]+)?( )?(.*)$/;
    # Actual key of parameter. Eg '!destination'
    my $pkey;

    for my $whichkey (@PossibleKeys)
    {
      my @key = grep {/$whichkey/} keys %$hParams;
      $pkey = $key[0] if (scalar(@key) and defined($key[0]));
      if (defined($pkey))
      {
        $hRequire{$PossibleKeys[0]} = 1;
        last;
      }
    }

    if (defined($pkey))
    {
      my ($not, $str) = $pkey =~ /^(!)?(.*)$/;
      push @ret, "!" if (defined($not) and not grep {$str} @done);
      push @done, $str;
      if (ref($mapval) eq 'HASH')
      {
        # orkey - possible hParam value
        foreach my $orkey (keys %$mapval)
        {
          if ($orkey =~ /$hParams->{$pkey}/)
          {
            push @ret, $mapval->{$orkey};
          }
        }
      }
      elsif (ref(\$mapval) eq 'SCALAR')
      {
        next if(defined($mapfunc) and $mapfunc eq 'bool' and not defined($hParams->{$pkey}));
        push @ret, $mapval if (defined($mapval) and length($mapval));
        if (defined($mapfunc) and length($mapfunc))
        {
          if ($mapfunc eq 'lc')
          {
            push @ret, lc($hParams->{$pkey});
          }
          elsif ($mapfunc eq 'uc')
          {
            push @ret, uc($hParams->{$pkey});
          }
          elsif ($mapfunc eq 'qq')
          {
            push @ret, "\"" . $hParams->{$pkey} . "\"";
          }
          elsif ($mapfunc eq 'bool')
          {
            # Do nothing
          }
          elsif ($mapfunc eq 'ip')
          {
            push @ret, $self->_cidr_ip($hParams->{$pkey});
          }
        }
        else
        {
          push @ret, $hParams->{$pkey};
        }
      }
    }
  }
  if (not grep {$_ == 0} values(%hRequire))
  {
    return join(' ', @ret) if (scalar(@ret));
  }
  else
  {
    warn "Required fields not defined: [" . 
      join("] [", grep {$hRequire{$_} == 0} keys(%hRequire)) . "]\n";
  }
}

# Return a valid CIDR IP address if possible or undef
sub _valid_ip
{
  my ($self, $ip) = @_;
  $ip =~ s|/[0-9]+||;

  return (defined($ip) and inet_aton($ip) ? 1 : 0);
}

# Check that a base address is in the bounds of a subnet
sub _valid_cidr
{
  my ($self, $cidr) = @_;
  return 0 if (not defined($cidr));

  my ($network, $subnet) = split("/", $cidr);
  return 0 if (not defined($network) or not defined($subnet));

  my $inet = unpack('N', inet_aton($network));
  my $mask = (2**32) - (2**(32-$subnet));

  my $tmask = ($inet | $mask);

  return ($tmask <= $mask ? 1 : 0);
}

# Return a valid CIDR address
sub _cidr_ip
{
  my ($self, $ip) = @_;

  if (not $self->_valid_ip($ip))
  {
    return;
  }
  elsif ($self->_valid_cidr($ip))
  {
    return $ip;
  }
  else
  {
    return "$ip/32";
  }
}

sub _each_kv
{
  my ($self, $data, $name) = @_;

  $self->{nf} = {} if (not defined($self->{nf}) and not ref($self->{nf}) eq 'HASH');

  $name = (defined($name) ? $name : 'each_kv');

  if (defined($data))
  {
    if (ref($data) eq 'ARRAY')
    {
      if (scalar(@$data) % 2)
      {
        warn "Uneven array - nothing done\n";
        return 0;
      }
      else
      {
        $self->{kv}{$name} = [@$data];
        $self->{kv}{$name . 'orig'} = [@$data];
        return 1;
      }
    }
    elsif (ref(\$data) eq 'SCALAR' and defined($self->{kv}{$name . 'orig'}))
    {
      my $bool;
      if ($data =~ /key/)
      {
        $bool = 0;
      }
      elsif ($data =~ /val/)
      {
        $bool = 1;
      }
      else
      {
        return;
      }
  
      my @ret;
      for my $num (0 .. $#{$self->{kv}{$name . 'orig'}})
      {
        push @ret, $self->{kv}{$name . 'orig'}[$num] if ($num % 2 == $bool);
      }
  
      return @ret;
    }
  }

  if (ref($self->{kv}{$name}) ne 'ARRAY' or not scalar(@{$self->{kv}{$name}}))
  {
    delete $self->{kv}{$name};
    delete $self->{kv}{$name . 'orig'};
    return;
  }

  my $k = shift @{$self->{kv}{$name}};
  my $v = shift @{$self->{kv}{$name}};

  return $k, $v;
}

sub _expand
{
  my ($self, $sets) = @_;

  if (! @$sets)
  {
    return [ [] ];
  }
  else
  {
    my $first_set = $sets->[0];
    my $cross = $self->_expand([ @$sets[1 .. $#$sets] ]);

    return [
      map {
        my $item = $_; 
        map { [$item, @$_] } @$cross 
      } @$first_set
    ];
  }
}


1;

__END__

=head1 AUTHOR

Shawn Wilson E<lt>swilson@korelogic.comE<gt>

=head1 COPYRIGHT

Copyright 2014- Shawn Wilson

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
# Lookup table to make sure elements are in order

