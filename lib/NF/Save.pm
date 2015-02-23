package NF::Save;

use strict;
use warnings;
use 5.010;

use subs qw(warn);

our $VERSION = '0.01';

use Carp qw(cluck);
use Data::Dumper;
use Socket;
use Storable qw(dclone);

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

my $raIPTLookup = [
  'src' => 'srcdst',
  'dst' => 'srcdst',
  'in' => 'io_if',
  'out' => 'io_if',
  'proto' => 'proto',
  'owner' => 'owner',
  'match' => 'match',
  'list' => 'list_set',
  'tcp' => 'tcp_udp',
  'udp' => 'tcp_udp',
  'icmp' => 'icmp',
  'conntrack' => 'ct',
  'limit' => 'limit',
  'comment' => 'comment',
  'jump' => 'jump',
];

# Policy map for standard table chains
my $rhPolicy = {
  'filter'  => {
    'INPUT'       => 'DROP',
    'OUTPUT'      => 'DROP',
    'FORWARD'     => 'DROP',
  },
  'mangle'  => {
    'PREROUTING'  => 'ACCEPT',
    'INPUT'       => 'ACCEPT',
    'FORWARD'     => 'ACCEPT',
    'OUTPUT'      => 'ACCEPT',
    'POSTROUTING' => 'ACCEPT',
  },
  'nat'     => {
    'PREROUTING'  => 'ACCEPT',
    'INPUT'       => 'ACCEPT',
    'OUTPUT'      => 'ACCEPT',
    'POSTROUTING' => 'ACCEPT',
  },
  'raw'     => {
    'OUTPUT'      => 'ACCEPT',
    'POSTROUTING' => 'ACCEPT',
    'PREROUTING'  => 'ACCEPT',
  },
};

# TODO implement this
# What --syn etc get expanded into - not implemented yet
my $rhFlags = {
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

=cut

sub new
{
  my ($class, $hParams) = @_;

  if (exists($hParams->{Trace}) and $hParams->{Trace} == 1)
  {
    *warn = \&cluck;
  }
  else
  {
    *warn = sub { &CORE::warn };
  }

  my $useParams = {
    'nf' => {
      'filter' => {
        'INPUT' => [],
        'OUTPUT' => [],
        'FORWARD' => [],
      },
    },
    'set' => {},
    'nf comment' => [],
    'set comment' => [],
  };
  $useParams->{uids} = (
    (exists($hParams->{UIDs}) and ref($hParams->{UIDs}) eq 'HASH') ?
    $hParams->{UIDs} : {}
  );

  if (exists($hParams->{IPTLookup}) and ref($hParams->{IPTLookup}) eq 'ARRAY' and
    scalar($hParams->{IPTLookup}) > 0)
  {
    for my $i (@{$hParams->{IPTLookup}})
    {
      $raIPTLookup->[$i] = $hParams->{IPTLookup}[$i]
        if (scalar($hParams->{IPTLookup}[$i]));
    }
  }
  $useParams->{lookup} = $raIPTLookup;

  # Overright default
  $hParams->{Policy} //= {};
  $useParams->{Policy} = {%$rhPolicy, %{$hParams->{Policy}}};

  $useParams->{flags} = (
    (exists($hParams->{Flags}) and ref($hParams->{Flags}) eq 'ARRAY') ?
    $hParams->{flags} : $rhFlags
  );

  $useParams->{useipset} = $hParams->{UseIPSET} // 0;

  $useParams->{precheck} = $hParams->{PreCheck} // 0;

  return bless $useParams, $class;
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

=item useipset($bool)

Change whether ipset is used bu default.

=cut

sub useipset
{
  my ($self, $bool) = @_;

  if (defined($bool))
  {
    $self->{useipset} = $bool;
  }
  else
  {
    return $self->{useipset};
  }
}

=item get_policy($chain, $table)

Get the policy for a chain

=cut

sub get_policy
{
  my ($self, $chain, $table) = @_;

  $table //= "filter";

  if (exists($self->{Policy}{$table}{$chain}))
  {
    return $self->{Policy}{$table}{$chain};
  }
  else
  {
    return;
  }
}

=item get_header($chain, $table)

Get header policies for iptable-save

=cut

sub get_header
{
  my ($self, $chain, $table) = @_;

  $table //= "filter";

  if ($self->get_policy($chain, $table))
  {
    return ":$chain " . $self->get_policy($chain, $table) . " [0:0]";
  }
  else
  {
    return ":$chain - [0:0]";
  }
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

  return if (defined($name) and not $self->is_ipset($name));
  my @iter = ($name // keys(%{$self->{ipset}}));

  my @ret;
  foreach my $name (@iter)
  {
    my $data = $self->{ipset}{$name};
    my $type = $data->{type} // 'hash:net';
    my $family = $data->{family} // 'inet';
    my $hashsize = $data->{hashsize} // 1024;
    my $maxelen = $data->{maxelen} // 65536;

    push @ret, "create $name $type family $family hashsize $hashsize maxelen $maxelen";
    push @ret, map {"add $name $_"} @{$data->{list}};
  }

  push @ret, @{$self->{'set comment'}};

  return @ret;
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

  my @ret;
  foreach my $table ($self->get_tables())
  {
    push @ret, "*$table", @{$self->save_table($table)}, "COMMIT";
  }

  push @ret, @{$self->{'nf comment'}};

  return @ret;
}

=item get_tables()

Return a list of tables

=cut

sub get_tables
{
  my ($self) = @_;

  return ($self->_sortpre(
    [keys %{$self->{nf}}],
    [qw/raw nat mangle filter/]
  ));
}

=item save_table($table)

Return an iptables-save array for all chains in a table (default to filter if no table is supplied)

=cut

sub save_table
{
  my ($self, $table) = @_;
  $table //= 'filter';

  return undef if (not $self->is_table($table));

  my (@head, @chains);
  foreach my $chain ($self->get_chains($table))
  {
    push @head, $self->get_header($chain, $table);
    push @chains, @{$self->save_chain($chain, $table)};
  }

  my @ret;

  push @ret, @head, @chains;

  return [@ret];
}

=item get_chain($table)

Return a list of chains for a table

=cut

sub get_chains
{
  my ($self, $table) = @_;

  return undef if (not $self->is_table($table));
  return (
    $self->_sortpre(
      [keys(%{$self->{nf}{$table}})], 
      [qw/PREROUTING INPUT FORWARD OUTPUT POSTROUTING/],
    )
  );
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
  $self->_each_kv($self->{lookup}, 'lookup');

  while (my ($listkey, $comp) = $self->_each_kv(undef, 'lookup'))
  {
    my $key = $self->_return_valid_param($listkey, $hParams);
    next if (not defined($key));

    my $data = $self->_param_str($key, $hParams->{$key});
    my $ret = $self->_comp($comp, $data);

    if (defined($ret) and ref($ret) eq 'ARRAY')
    {
      push @iptparts, $ret;
    }
    else
    {
      warn "No data or invalid data type returned for " . Dumper($data) .
        "listkey [$listkey] key [$key] comp [$comp]\n";
    }
  }

  return [@iptparts];
}

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

=item rule($chain, $rule, $table, $func)

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

  # Make sure the hash is immutable
  $rule = dclone($rule);

  if ($self->{precheck} and not $self->check_rule($rule))
  {
    warn "Invalid rule " . Dumper($rule) . "\n";
    return;
  }

  $self->{nf}{$table} = {map {$_ => []} keys %{$rhPolicy->{$table}}} 
    unless (ref($self->{nf}{$table}) eq 'HASH');
  $self->{nf}{$table}{$chain} = () unless (ref($self->{nf}{$table}{$chain}) eq 'ARRAY');

  return $self->_ipt_do($rule, $table, $chain, $do, $num);
}

=item check_rule

Return true if the parameters in the rule structure make up a valid rule.

=cut

sub check_rule
{
  my ($self, $data) = @_;

  my $ret = $self->assemble($data);

  return (ref($ret) eq 'ARRAY' and scalar(@$ret) ? 1 : 0);
}

=item is_user($username)

Return true if user has been defined.

=cut

sub is_user
{
  my ($self, $user) = @_;

  return (exists($self->{uids}{$user}) ? 1 : 0);
}

=item comment($str, $where)

Add a comment that will be displayed in iptables/ipset output

=cut

sub comment
{
  my ($self, $str, $where) = @_;
  $where //= "nf";

  $str = "# $str";

  if ($where =~ /^(ipt|nf)/)
  {
    push @{$self->{'nf comment'}}, $str;
  }
  elsif ($where =~ /^(ips|set)/)
  {
    push @{$self->{'set comment'}}, $str;
  }
  else
  {
    push @{$self->{'nf comment'}}, $str;
    push @{$self->{'set comment'}}, $str;
  }
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

=back

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

  if (($hParams->{useipset} and $hParams->{useipset} != 0) or 
    ($self->{useipset} and $self->{useipset} != 0))
  {
    warn "Set [$name] has not been defined\n" if (not $self->is_ipset($name));
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
# a third hash with alternate key map, and required fields.
# The definition of "map" is a balanced array of:
# <key of input data structure [function]> => <value>
# Or
# <key of input data structure> => {<value of input data structure> => <value to use>}
# The later form is used to yield different outputs depending on the input value
sub _str_map
{
  my ($self, $hParams, $map, $alt, $require) = @_;

  # Setup hash to make sure that all fields that are required are present
  my %hRequire = map {$_ => 0} @$require;

  # Make sure results are oldered from the even map array
  $self->_each_kv($map, 'str_map');

  my (@ret, @done);
  while (my ($mapkey, $mapval) = $self->_each_kv(undef, 'str_map'))
  {
    # TODO Make mapfunc an array so that multiple things can be done
    # mapped string and function. Eg 'name' and 'lc'
    my ($mapstr, $mapfunc) = $mapkey =~ /^([^ ]+) ?(.*)$/;

    my @PossibleKeys;
    push @PossibleKeys, $mapstr if (defined($mapstr) and length($mapstr));
    push @PossibleKeys, $alt->{$mapstr} 
      if (defined($alt) and ref($alt) eq 'HASH' and defined($alt->{$mapstr}));

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

        push @ret, $self->_str_map_transform($hParams->{$pkey}, $mapfunc);
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
      join("] [", grep {$hRequire{$_} == 0} keys(%hRequire)) . "] " .
      Dumper($hParams) . "\n";
    return;
  }
}

# Transform data based on mapfunc
sub _str_map_transform
{
  my ($self, $data, $mapfunc, $lookup) = @_;

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
      # Do nothing
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
      if (not exists($lookup->{$data}) or not defined($lookup->{$data}))
      {
        warn "[$data] does not exist in lookup.\n";
        return;
      }

      return $lookup->{$data};
    }
  }
  else
  {
    return $data;
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

=head1 TODO

- Some tests fail (prove -lbv t/*.t)
  - mist.t: all tests now pass
  - ipt_do.t: does not pass
- Need more tests and use cases
  - Need to handle more modules (and probably separate that namespace out)
  - code is kinda brittle
- Split find places to split this into submodules
- Might want to look at naming in the API (->save saves a iptables rule and 
    ->ipset saves a set for ipset - seems off)
- Integration with libiptc using FFI or similar instead of using IPC
  - Consider making a different module since the purpose of this is just to 
    dump information
- Make a debug option

=head1 AUTHOR

Shawn Wilson E<lt>swilson@korelogic.comE<gt>

=head1 COPYRIGHT

Copyright 2014- Shawn Wilson

=head1 LICENSE

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.
# Lookup table to make sure elements are in order

