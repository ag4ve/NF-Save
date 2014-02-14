package NF::Save;

use strict;
use warnings;
use 5.010;

our $VERSION = '0.01';

use Socket;

# Lookup table to make sure elements are in order
my $raIPTLookup = [
  {
    'key' => "src",
    'comp' => "srcdst",
  }, {
    'key' => "dst",
    'comp' => "srcdst",
  }, {
    'key' => "in",
    'comp' => "io_if",
  }, {
    'key' => "out",
    'comp' => "io_if",
  }, {
    'key' => "proto",
    'comp' => "proto",
  }, {
    'key' => 'owner',
    'comp' => "owner",
  }, {
    'key' => "mod",
    'comp' => "nf_module",
  }, {
#    'key' => [qw/list set/],
#    'comp' => 'list_set',
#  }, {
#    'key' => [qw/match tcp/],
#    'comp' => 'tcp_udp',
#  }, {
#    'key' => [qw/match udp/],
#    'comp' => 'tcp_udp',
#  }, {
#    'key' => [qw/match icmp/],
#    'comp' => 'icmp',
#  }, {
    'key' => 'conntrack',
    'comp' => "ct",
  }, {
    'key' => "limit",
    'comp' => "limit",
  }, {
    'key' => "comment",
    'comp' => "comment",
  }, {
    'key' => "jump",
    'comp' => "jump",
  },
];

# What --syn get expanded into - not implemented yet
my $raSynFlags = [
  'FIN,SYN,RST,ACK SYN',
];

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

# Return NF data structure
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

# Check if a chain is defined
sub is_chain
{
  my ($self, $chain, $table) = @_;

  return (($self->is_table($table) and exists($self->{nf}{$table}{$chain})) ? 1 : 0);
}

# Check if a table is defined
sub is_table
{
  my ($self, $table) = @_;

  return (exists($self->{nf}{$table}) ? 1 : 0);
}

sub set
{
  my ($self, $name, $list, $opts) = @_;

  return undef unless (defined($name) and 
    defined($list) and ref($list) eq 'ARRAY');

  my $aIPs;
  @$aIPs = grep {defined($_)} map {$self->_valid_ip($_)} @$list;

  my $return = (scalar(@$list) - scalar(@$aIPs));

  if (not $self->is_set($name))
  {
    $self->{set}{$name} = {'list' => $aIPs};
  }
  else
  {
    push @{$self->{set}{$name}{list}}, @$aIPs;
  }

  if (defined($opts) and ref($opts) eq 'HASH')
  {
    foreach my $key (keys %$opts)
    {
      $self->{set}{$name}{$key} = $opts->{$key};
    }
  }

  return ($return ? -$return : 1);
}

# Return a set save array for a given set or all sets if no valid name is given
sub get_set
{
  my ($self, $name) = @_;

  $name = ($self->is_set($name) ? $name : undef);
  my @iter = ($name // keys(%{$self->{set}}));

  my @return;
  foreach my $name (@iter)
  {
    my $data = $self->{set}{$name};
    my $type = $data->{type} // 'hash:net';
    my $family = $data->{family} // 'inet';
    my $hashsize = $data->{hashsize} // 1024;
    my $maxelen = $data->{maxelen} // 65536;

    push @return, "create $name $type family $family hashsize $hashsize maxelen $maxelen";
    push @return, map {"add $name $_"} @{$data->{list}};
  }

  return [@return];
}

# Check if a set exists
sub is_set
{
  my ($self, $name) = @_;

  return (exists($self->{set}{$name}) ? 1 : 0);
}

# Return data for a set
sub get_set_data
{
  my ($self, $name) = @_;

  if ($self->is_set($name))
  {
    return $self->{set}{$name};
  }
  else
  {
    return undef;
  }
}

# Return an array with iptables-save data
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

# Return a list of tables
sub get_tables
{
  my ($self) = @_;

  return (keys %{$self->{nf}});
}

# Return an iptables-save array for a table
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

# Return a list of chains for a table
sub get_chains
{
  my ($self, $table) = @_;

  return undef if (not $self->is_table($table));
  return (keys %{$self->{nf}{$table}});
}

# Return an array with iptables-save data for one chain
sub save_chain
{
  my ($self, $chain, $table) = @_;
  $table //= 'filter';

  return undef unless (defined($chain) and $self->is_chain($chain, $table));

  my @return;
  foreach my $rule ($self->get_rules($chain, $table))
  {
    push @return, $self->assemble($rule);
  }

  return @return;
}

# Return data structure of rules in a chain
sub get_rules
{
  my ($self, $chain, $table) = @_;
  $table //= 'filter';

  return undef if (not $self->is_chain($chain, $table));
  return @{$self->{nf}{$table}{$chain}};
}

# Put an iptables rule for a data structure definition
sub assemble
{
  my ($self, $hParams) = @_;

  my @iptparts;
  for my $part (@{$self->{lookup}})
  {
    my $pkey = $part->{key};
    my $pcomp = '_' . $part->{comp};
    my $pval = $hParams->{$pkey};

    # Next if the part isn't defined in the rule
    next unless (defined($pval));

    if (not $self->can($pcomp))
    {
      warn "No method [$pcomp] - skipping\n";
      next;
    }

    my $data;
    if (ref(\$pval) eq 'SCALAR' or ref($pval) eq 'ARRAY')
    {
      $data = {'name' => $pval};
    }
    else
    {
      $data = $pval;
    }

    push @iptparts, $self->$pcomp($data);
  }

  return [join(' ', @iptparts)];
}

# An interface designed to look fairly similar to the iptables cli
#
# The tcp '--syn' and '! --syn' options add masks from individual from
# the $raSynFlags arrayref
#
# The big difference is that the chain is seperate from the action
# This:
# iptables -I INPUT 5 -j ACCEPT
# Turns into this:
# ipt('INPUT', '-j ACCEPT', undef, 'I 5');
# The default is to append to the filter table, which means the pattern is:
# ipt('INPUT', '-j ACCEPT');
# Delete and replace have been implemented for completeness - for replace:
# ipt('OUTPUT', -j ACCEPT', 'filter', 'R 5');
sub rule
{
  my ($self, $chain, $rule, $table, $func) = @_;

  $table //= 'filter';
  $func //= 'A';
  my $do;
  $do = uc substr($1, 0, 1)
    if ($func =~ /^(I(NSERT)?|A(PPEND)?|D(ELETE)?|R(EPLACE)?)\b/i);

  return if ($func and not $do);

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

# Process a full iptables rule into the data structure
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

  if (not defined($hParams->{ip}) or not defined($hParams->{direction}) or
    not $self->_valid_cidr($hParams->{ip}))
  {
    warn "No direction or IP address defined - nothing done";
    return undef;
  }

  my @str;
  push @str, '!' if ($hParams->{not});
  push @str, ($hParams->{direction} =~ /src/i ? '-s' : '-d');
  push @str, $hParams->{ip};

  return [join(" ", @str)];
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

  my @str;
  push @str, '!' if ($hParams->{not});
  push @str, ($hParams->{direction} =~ /in/i ? '-i' : '-o');
  push @str, $hParams->{if};

  return [join(" ", @str)];
}

# Return an array of protocol strings
sub _proto
{
  my ($self, $hParams) = @_;

  return undef unless (defined($hParams->{proto}));

  $hParams->{proto} = lc($hParams->{proto});

  my @str;
  push @str, "-p " . $hParams->{proto};
  push @str, "-m " . $hParams->{match} if (defined($hParams->{match}));
  return [join (" ", @str)]
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

  my @str;
  push @str, "-m owner";
  push @str, "--uid-owner $uid" if(defined($uid));
  return [join(" ", @str)];
}

# Return an array of IP address match strings or a set name
sub _list_set
{
  my ($self, $hParams) = @_;
  my $name = $hParams->{name};
  return undef unless (exists($self->{set}{$name}{list}) and
    ref($self->{set}{$name}{list}) eq 'ARRAY');
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
    warn "Set [$name] has not been defined\n" unless ($self->is_set($name));
    push @return, "-m set --match-set $name " . join(",", sort {$b cmp $a} keys(%hDirection));
  }
  else
  {
    my @list = @{$self->{set}{$name}{list}}; 
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

# Return an array of TCP or UDP protocol match strings
sub _tcp_udp
{
  my ($self, $hParams) = @_;

  my @str;
  push @str, '!' if ($hParams->{not});
  push @str, '-p ' . lc($hParams->{name}) . ' -m ' . lc($hParams->{name});
  push @str, '--sport ' . $hParams->{sport} if (defined($hParams->{sport}));
  push @str, '--dport ' . $hParams->{dport} if (defined($hParams->{dport}));
  push @str, '--tcp-flags ' . $hParams->{flags} if (defined($hParams->{flags}));

  return [join(" ", @str)];
}

# Return an array of ICMP protocol match strings
sub _icmp
{
  my ($self, $hParams) = @_;

  my @str;
  push @str, '!' if ($hParams->{not});
  push @str, '-p ' . lc($hParams->{name}) . ' -m ' . lc($hParams->{name});
  push @str, '--icmp-type ' . $hParams->{type} if (defined($hParams->{type}));

  return [join(" ", @str)];
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
  return undef unless (defined($hParams->{name}));
  my $jump = $hParams->{name};
  warn "Assuming wrong case for [$jump] - matching against [" . uc($jump) . "]\n"
    if ($jump =~ /[a-z]/ and $jump =~ /^(LOG|REJECT|CT|SNAT|DNAT)$/i);

  my @pstr;
  if (uc($jump) eq 'LOG')
  {
    (push @pstr, "--log-prefix \"" . $hParams->{prefix} . "\"")
      if (defined($hParams->{prefix}));
    push @pstr, "--log-tcp-options" if ($hParams->{tcp});
    push @pstr, "--log-ip-options" if ($hParams->{ip});
    push @pstr, "--log-uid" if ($hParams->{uid});
  }
  elsif (uc($jump) eq 'REJECT')
  {
    push @pstr, "--reject-with icmp-port-unreachable"
      if ($hParams->{with});
  }
  elsif (uc($jump) eq 'CT')
  {
    push @pstr, "--notrack" if ($hParams->{notrack});
  }
  elsif (uc($jump) eq 'SNAT')
  {
    if ($hParams->{src})
    {
      my $ip = $self->_valid_ip($hParams->{src});
      push @pstr, "--to-source $ip" if ($ip);
    }
  }
  elsif (uc($jump) eq 'DNAT')
  {
    if ($hParams->{dst})
    {
      my $ip = $self->_valid_ip($hParams->{dst});
      push @pstr, "--to-destination $ip";
    }
  }

  my $str = "-j $jump";
  $str .= " " . join(" ", @pstr) if (@pstr);

  return [$str];
}

# Return a valid CIDR IP address if possible or undef
sub _valid_ip
{
  my ($self, $ip) = @_;

  return undef if (grep {$_ > 255} split(/\./, [split('/', $ip)]->[0]));

  $ip = $self->_cidr_ip($ip);

  return ($self->_valid_cidr($ip) ? $ip : undef);
}

# Check that a base address is in the bounds of a subnet
sub _valid_cidr
{
  my ($self, $cidr) = @_;

  my ($network, $subnet) = split("/", $cidr);

  return 1 unless $subnet;

  my $inet = unpack('N', inet_aton($network));
  my $mask = (2**32) - (2**(32-$subnet));

  my $tmask = ($inet | $mask);

  return ($tmask <= $mask ? 1 : 0);
}

# Return a valid CIDR address
sub _cidr_ip
{
  my ($self, $ip) = @_;

  return $ip if (scalar(split('/', $ip)) == 2);

  return "$ip/32";
}



1;

