package NF::Save::Helper;

use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);
our @EXPORT = qw/
  _return_valid_param
  _param_str
  _comp
  _ipt_do
  _srcdst
  _io_if
  _proto
  _owner
  _list_set
  _match
  _tcp_udp
  _icmp
  _ct
  _limit
  _comment
  _jump
  _str_map
  _str_map_transform
  _check_type
  _valid_ip
  _valid_cidr
  _cidr_ip
  _each_kv
  _expand
  _sortpre
/;
 
use Socket;
use Data::Dumper;

=encoding utf8

=head1 NAME

NF::Save::Helper - Module for storing, parsing, and restoring netfilter/iptables and ipset data

=head1 SYNOPSIS

  use NF::Save::Helper;

=head1 DESCRIPTION

Misc helper methods for NF::Save

=cut

# Confirm the value of the listkey is a base of a key of the hash
sub _return_valid_param
{
  my ($self, $listkey, $hParams) = @_;

  # If a key has been used in the data correctly
  my @key = grep {/^!?$listkey$/i} keys %$hParams;
  if (scalar(@key) > 1)
  {
    warn "Multiple keys with similar names [" . 
      join("] [", @key) . "] - Moving on\n";
    return;
  }
  elsif (scalar(@key) == 0)
  {
    return;
  }
  else
  {
    return $key[0];
  }
}

# Return part of the rule when passed the name of the private method and a hash.
sub _param_str
{
  my ($self, $key, $val) = @_;

  my $data;
  if (ref(\$val) eq 'SCALAR')
  {
    $data = {'name' => $val};
  }
  elsif (ref($val) eq 'ARRAY')
  {
    $data = {'name' => join(' ', @$val)};
  }
  elsif (ref($val) eq 'HASH')
  {
    $data = $val;
  }
  $data->{key} = $key if (not defined($data->{key}));

  return $data;
}

sub _comp
{
  my ($self, $comp, $data) = @_;

  $comp = '_' . $comp;

  if (not $self->can($comp))
  {
    warn "No method [$comp] - skipping\n";
    return;
  }

  return $self->$comp($data);
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
    }, [qw/
      direction
      ip
    /],
  )];
}

# Return an array of input/output interface strings
sub _io_if
{
  my ($self, $hParams) = @_;

  return [$self->_str_map($hParams, [
      'direction' => {
        'in' => "-i",
        'out' => "-o",
      },
      'if' => "",
    ], {
      'if' => "name",
      'direction' => "key",
    }, [qw/
      direction 
      if
    /],
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

  return [$self->_str_map($hParams, [
      'name bool'        => "-m owner",
      'owner %owner' => "--uid-owner",
    ], {
      'owner' => "name",
    }, [qw/
      owner
    /], {
      "owner" => $self->{uids}
    }
  )];
}

# Return an array of IP address match strings or a set name
sub _list_set
{
  my ($self, $hParams) = @_;

  my $name = $hParams->{name};
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

  if (($hParams->{useipset} and $hParams->{useipset} != 0) or 
    ($self->{useipset} and $self->{useipset} != 0))
  {
    warn "Set [$name] has not been defined\n" if (not $self->is_ipset($name));
    push @return, "-m set --match-set $name " . join(",", sort {$b cmp $a} keys(%hDirection));
  }
  else
  {
    if (not exists($self->{ipset}{$name}{list}) and
      ref($self->{ipset}{$name}{list}) ne 'ARRAY')
    {
      warn "No list of name [$name]\n";
      return;
    }
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
      'flags %flags' => "--tcp-flags",
    ], {
      'name' => "key"
    }, [qw/
      name
    /], {
      'flags' => $self->{flags}
    }
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
    ], {
      'name' => "key"
    }, [qw/
      name
    /],
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
    return;
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
# a third hash with alternate key map, required fields, and a lookup hash.
# The definition of "map" is a balanced array of:
# <key of input data structure [function]> => <value>
# Or
# <key of input data structure> => {<value of input data structure> => <value to use>}
# The later form is used to yield different outputs depending on the input value
# Lookup is a hashref of hashes whose value (string) can be substituted for the value 
# of params if the key of lookup says to use it.
sub _str_map
{
  my ($self, $hParams, $map, $alt, $require, $lookup) = @_;

  return if (not $self->_check_type([qw/HASH ARRAY HASH ARRAY HASH/], '>', 1, 1, @_[1 .. $#_]));

  # Setup hash to make sure that all fields that are required are present
  my %hRequire = map {$_ => 0} @$require;

  # Make sure results are oldered from the even map array
  $self->_each_kv($map, 'str_map');

  my (@ret, @done);
  while (my ($mapkey, $mapval) = $self->_each_kv(undef, 'str_map'))
  {
    my @maps = split(' ', $mapkey);
    next if (not exists($maps[0]));
    my $mapstr = $maps[0];

    my @PossibleKeys;
    push @PossibleKeys, $mapstr if (defined($mapstr) and length($mapstr));
    push @PossibleKeys, $alt->{$mapstr} 
      if (defined($alt) and defined($alt->{$mapstr}));

    # [Param Key] Get the actual key from the params. Eg '!destination'
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

    next if (not defined($pkey));

    my ($not, $str) = $pkey =~ /^(!)?(.*)$/;
    # TODO Not sure why we're checking @done here.
    push @ret, "!" if (defined($not) and not grep {$str} @done);
    # An index of keys that have already been processed.
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
      # Modify the key based on each map option
      my $tret = $hParams->{$pkey};
      foreach my $tmap (@maps[1 .. $#maps])
      {
        $tret = $self->_str_map_transform($tret, $tmap, $lookup);
      }
      if (defined($tret))
      {
        push @ret, $mapval if (defined($mapval));
        push @ret, $tret;
      }
    }
  }

  if (not grep {$_ == 0} values(%hRequire))
  {
    return join(' ', grep {defined($_) and length($_) > 0} @ret) if (scalar(@ret));
  }
  else
  {
    warn "Required fields not defined: [" . 
      join("] [", grep {$hRequire{$_} == 0} keys(%hRequire)) . "] " .
      Dumper($hParams) . "\n";
    return;
  }
}

# Transform data based on mapfunc
sub _str_map_transform
{
  my ($self, $data, $mapfunc, $lookup) = @_;

  return if (not defined($data));

  if (defined($mapfunc) and length($mapfunc))
  {
    if ($mapfunc eq 'lc')
    {
      return lc($data);
    }
    elsif ($mapfunc eq 'uc')
    {
      return uc($data);
    }
    elsif ($mapfunc eq 'qq')
    {
      return "\"" . $data . "\"";
    }
    elsif ($mapfunc eq 'bool')
    {
      return if (not defined($data));
    }
    elsif ($mapfunc eq 'ip')
    {
      return $self->_cidr_ip($data);
    }
    # Key to lookup from
    if ($mapfunc =~ /^%(.*)/)
    {
      my $key = $1;
      if (not defined($lookup))
      {
        warn "A lookup hash was wanted but not defined.\n";
        return;
      }

      if (exists($lookup->{$key}{$data}) and defined($lookup->{$key}{$data}))
      {
        return $lookup->{$key}{$data};
      }
      else
      {
        warn "[$data] does not exist in lookup.\n" if (defined($self->{trace}));
        return $data;
      }
    }
  }
  else
  {
    return $data;
  }
}

# Check a list of types against an array of data
# Second option is whether there can be more data than types (>) or 
# types than data (<)
sub _check_type
{
  my ($self, $types, $which_more, $warn, $undef, @data) = @_;

  if (ref($types) ne 'ARRAY')
  {
    warn "Type must be an arrayref [" . ref($types) . "].\n";
    return;
  }

  $which_more //= '=';
  if ($which_more eq '<' and scalar(@$types) > scalar(@data))
  {
    warn "More parameters than data\n" if ($warn);
    return;
  }
  elsif ($which_more eq '>' and scalar(@$types) < scalar(@data))
  {
    warn "More data than parameters\n" if ($warn);
    return;
  }
  elsif ($which_more eq '=' and scalar(@$types) != scalar(@data))
  {
    warn "Number of data not equal to the number of parameters\n" if ($warn);
    return;
  }

  for my $i (0 .. $#{$types})
  {
    return 1 if (not defined($data[$i]));
    if (($types->[$i] =~ /^(ARRAY|HASH|CODE)$/ and ref($data[$i]) ne $types->[$i]) or 
      ($types->[$i] eq 'SCALAR' and ref(\$data[$i]) ne $types->[$i]) or
      ($undef and not defined(($data[$i]))))
    {
      warn "[$i] " . ref($data[$i]) . " not equal to " . $types->[$i] . " " . 
        Dumper($data[$i]) . "\n" if ($warn);
      return;
    }
  }
  return 1;
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

# Use an array of pairs like a hash
# Can take a 'name' for a data structure and data can either be the data or 'keys' or 'values' to return all keys/values
sub _each_kv
{
  my ($self, $data, $name) = @_;

  $self->{kv} = {} if (not defined($self->{kv}) or ref($self->{kv}) ne 'HASH');

  $name = (defined($name) ? $name : 'each_kv');

  if (defined($data))
  {
    # Create named group
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
    # Return named keys or values
    elsif (ref(\$data) eq 'SCALAR' and defined($self->{kv}{$name . 'orig'}))
    {
      my ($bool, $match);
      if ($data =~ /^key[^ ]* ?(.*)/)
      {
        $bool = 0;
        $match = $1;
      }
      elsif ($data =~ /^val[^ ]* ?(.*)/)
      {
        $bool = 1;
        $match = $1;
      }
      else
      {
        return;
      }
  
      my @ret;
      my $raOrig = $self->{kv}{$name . 'orig'};
      for my $num (0 .. $#{$raOrig})
      {
        if ($num % 2 == $bool)
        {
          if (length($match) > 0)
          {
            my $cmp_num = ($bool ? $num - 1 : $num + 1);
            next if ($raOrig->[$cmp_num] !~ /$match/);
          }
          push @ret, $raOrig->[$num];
        }
      }
  
      return @ret;
    }
  }

  # Cleanup
  if (ref($self->{kv}{$name}) ne 'ARRAY' or not scalar(@{$self->{kv}{$name}}))
  {
    delete $self->{kv}{$name};
    delete $self->{kv}{$name . 'orig'};
    return;
  }

  # Return key/value pair
  my $k = shift @{$self->{kv}{$name}};
  my $v = shift @{$self->{kv}{$name}};

  return $k, $v;
}

# Expand arrays of arrays into an array of strings for each possibility
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

# Precede sort with possible presorted values from an array.
sub _sortpre
{
  my ($self, $data, $prevals) = @_;
  $prevals //= [];

  my $i = 1;
  my $pre = (ref($prevals) eq 'ARRAY' and scalar(@$prevals) ?
    {map {$_ => $i++} @$prevals} : {}
  );

  return (
    sort {
      return $pre->{$a} <=> $pre->{$b}
        if $pre->{$a} && $pre->{$b};
      return -1 if $pre->{$a};
      return +1 if $pre->{$b};
      return $a cmp $b;
    } @$data
  );
}


1;

__END__

