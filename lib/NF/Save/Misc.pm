package NF::Save::Misc;

use strict;
use warnings;
 
require Exporter;
our @ISA = qw(Exporter NF::Save::Helper);
our @EXPORT = qw/
  get
  is_chain
  is_table
  useipset
  get_policy
  get_header
  rule
  raw_rule
  check_rule
  is_user
  comment
  add_list
  get_ipset
  is_ipset
  get_ipset_data
  save
  get_tables
  save_table
  get_chains
  save_chain
  get_rules
  assemble
/;
 
use NF::Save::Helper;
use Data::Dumper;
use Storable qw(dclone);

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

  $self->{nf}{$table} = {map {$_ => []} keys %{$self->{Policy}{$table}}} 
    unless (ref($self->{nf}{$table}) eq 'HASH');
  $self->{nf}{$table}{$chain} = () unless (ref($self->{nf}{$table}{$chain}) eq 'ARRAY');

  return $self->_ipt_do($rule, $table, $chain, $do, $num);
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

=item add_list($name, @list, $opts)

Define an ipset list.

C<$name> is the name of the set
C<@list> is a list of addresses in the set
C<%opts> parameters for the set

=cut

# TODO only hash:net is assumed in the list - other types should be allowed and looked for
sub add_list
{
  my ($self, $name, $list, $opts) = @_;

  return if (not $self->_check_type([qw/SCALAR ARRAY HASH/], '>', 1, 1, @_[1 .. $#_]));
  return if (not defined($name) and 
    not defined($list) and ref($list) ne 'ARRAY');

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

  if (defined($opts))
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
    return;
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

  return if (not $self->is_table($table));

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

  return if (not $self->is_table($table));
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

  return if (not $self->is_chain($chain, $table));
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


1;

__END__

