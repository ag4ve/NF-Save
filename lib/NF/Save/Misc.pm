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
 
use NF::Save::Helper qw(:all);
use Data::Dumper;
use Storable qw(dclone);

=item get($sChain, $sTable)

Return the internal data structure used to store iptables information

=cut

sub get
{
  my ($oSelf, $sChain, $sTable) = @_;
  $sTable //= 'filter';

  if (not $oSelf->is_table($sTable) or not defined($sChain))
  {
    return $oSelf->{nf};
  }
  elsif (not defined($sChain) or not $oSelf->is_chain($sChain, $sTable))
  {
    return $oSelf->{nf}{$sTable};
  }
  else
  {
    return $oSelf->{nf}{$sTable}{$sChain};
  }
}

=item is_chain($sChain, $sTable)

Check if a chain is defined (the filter table is assumed if none is given)

=cut

sub is_chain
{
  my ($oSelf, $sChain, $sTable) = @_;
  $sTable //= 'filter';

  return (($oSelf->is_table($sTable) and exists($oSelf->{nf}{$sTable}{$sChain})) ? 1 : 0);
}

=item is_table

Check if a table is defined

=cut

sub is_table
{
  my ($oSelf, $sTable) = @_;

  return (exists($oSelf->{nf}{$sTable}) ? 1 : 0);
}

=item useipset($sBool)

Change whether ipset is used by default.

=cut

sub useipset
{
  my ($oSelf, $sBool) = @_;

  if (defined($sBool))
  {
    $oSelf->{useipset} = $sBool;
  }
  else
  {
    return $oSelf->{useipset};
  }
}

=item get_policy($sChain, $sTable)

Get the policy for a chain

=cut

sub get_policy
{
  my ($oSelf, $sChain, $sTable) = @_;

  $sTable //= "filter";

  if (exists($oSelf->{Policy}{$sTable}{$sChain}))
  {
    return $oSelf->{Policy}{$sTable}{$sChain};
  }
  else
  {
    return;
  }
}

=item get_header($sChain, $sTable)

Get header policies for iptable-save

=cut

sub get_header
{
  my ($oSelf, $sChain, $sTable) = @_;

  $sTable //= "filter";

  if ($oSelf->get_policy($sChain, $sTable))
  {
    return ":$sChain " . $oSelf->get_policy($sChain, $sTable) . " [0:0]";
  }
  else
  {
    return ":$sChain - [0:0]";
  }
}

=item rule($sChain, $sRule, $sTable, $sFunc)

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
  my ($oSelf, $sChain, $sRule, $sTable, $sFunc) = @_;

  $sTable //= 'filter';
  $sFunc //= 'A';
  my $sDo;
  $sDo = uc(substr($1, 0, 1))
    if ($sFunc =~ /^(I(NSERT)?|A(PPEND)?|D(ELETE)?|R(EPLACE)?)\b/i);

  return if (not defined($sDo));

  my $sNum = (($sFunc =~ /\S+ ([0-9]+)/) ? $1 : '1');

  # Make sure the hash is immutable
  $sRule = dclone($sRule);

  if ($oSelf->{precheck} and not $oSelf->check_rule($sRule))
  {
    warn "Invalid rule " . Dumper($sRule) . "\n";
    return;
  }

  $oSelf->{nf}{$sTable} = {map {$_ => []} keys %{$oSelf->{Policy}{$sTable}}} 
    unless (ref($oSelf->{nf}{$sTable}) eq 'HASH');
  $oSelf->{nf}{$sTable}{$sChain} = () unless (ref($oSelf->{nf}{$sTable}{$sChain}) eq 'ARRAY');

  return $oSelf->_ipt_do($sRule, $sTable, $sChain, $sDo, $sNum);
}

=item raw_rule(@rules)

Process a full iptables rule into the data structure

=back

=cut

# TODO Untested and doesn't actually do anything
sub raw_rule
{
  my ($oSelf, $paRules) = @_;

  return unless (defined($paRules) and ref($paRules) eq 'ARRAY');

  my $return;
  foreach my $sRule (@{$paRules})
  {
    my $orig_rule = $sRule;

    my $sTable;
    {
      $sRule =~ s/^-t *([^ ]+) //;
      $sTable = $1 // 'filter';
    }

    my $sChain;
    {
      $sRule =~ s/^-A *([^ ]+) //;
      $sChain = $1;
    }

    my ($nsrc, $src);
    {
      $sRule =~ s/^(!)? -s *([0-9\.]+) //;
      $nsrc = $1;
      $src = $2;
    }

    my ($ndst, $dst);
    {
      $sRule =~ s/^(!)? -d *([0-9\.]+) //;
      $ndst = $1;
      $dst = $2;
    }

    my $mproto;
    {
      $sRule =~ s/^-m (tcp|TCP|udp|UDP|icmp|ICMP) //;
      $mproto = $1;
    }
      
    my ($sport, $dport, $flags, $type);
    if ($mproto =~ /tcp|udp/i)
    {
      {
        $sRule =~ s/^(?:--sport ([0-9:]+) )?(?:--dport ([0-9:]+) )?//;
        $sport = $1;
        $dport = $2;
      }
      $sRule =~ s/^ // if (defined($sport) or defined($dport));

      if ($mproto =~ /tcp/i)
      {
        $sRule =~ s/^--tcp-flags ([^ ]+) //;
        $flags = $1;
      }
    }
    elsif ($mproto =~ /icmp/i)
    {
      $sRule =~ s/^--icmp-type ([0-9]+) //;
      $type = $1;
    }

    my $owner;
    {
      $sRule =~ s/^-m owner --uid-owner ([^ ]+) //;
      $owner = $1;
    }

    my ($set, $setdir);
    {
      $sRule =~ s/^-m set --match-set ([^ ]+) ([^ ]+) //;
      $set = $1;
      $setdir = $2;
    }

    my $ct;
    {
      $sRule =~ s/^-m conntrack --ctstate ((?:(?:NEW|RELATED|ESTABLISHED|INVALID),?)+) //;
      $ct = $1;
    }

    my ($limit, $burst);
    {
      $sRule =~ s/^-m limit (?:--limit ([^ ]+) )?(?:--limit-burst ([^ ]+) )?//;
      $limit = $1;
      $burst = $2;
    }

    my $comment;
    {
      $sRule =~ s/^-m comment "([^"]+)" //;
      $comment = $1;
    }

    # TODO certain jumps can hava parameters
    # TODO can '-m tcp -m udp -m icmp' be used in one rule
    my $jump;
    {
      $sRule =~ s/^-j ([^ ]+)//;
      $jump = $1;
    }
    push @{$return->{$sChain}{$sTable}}, {
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
  my ($oSelf, $phData) = @_;

  my $paRet = $oSelf->assemble($phData);

  return (ref($paRet) eq 'ARRAY' and scalar(@$paRet) ? 1 : 0);
}

=item is_user($sUser)

Return true if user has been defined.

=cut

sub is_user
{
  my ($oSelf, $sUser) = @_;

  return (exists($oSelf->{uids}{$sUser}) ? 1 : 0);
}

=item comment($sComment, $sWhere)

Add a comment that will be displayed in iptables/ipset output

=cut

sub comment
{
  my ($oSelf, $sComment, $sWhere) = @_;
  $sWhere //= "nf";

  $sComment = "# $sComment";

  if ($sWhere =~ /^(ipt|nf)/)
  {
    push @{$oSelf->{'nf comment'}}, $sComment;
  }
  elsif ($sWhere =~ /^(ips|set)/)
  {
    push @{$oSelf->{'set comment'}}, $sComment;
  }
  else
  {
    push @{$oSelf->{'nf comment'}}, $sComment;
    push @{$oSelf->{'set comment'}}, $sComment;
  }
}

=item add_list($sName, @$paList, %$phOpts)

Define an ipset list.

C<$sName> is the name of the set
C<@$paList> is a list of addresses in the set
C<%$phOpts> parameters for the set

=cut

# TODO only hash:net is assumed in the list - other types should be allowed and looked for
sub add_list
{
  my ($oSelf, $sName, $paList, $phOpts) = @_;

  return if (not $oSelf->_check_type([qw/SCALAR ARRAY HASH/], '>', 1, 1, @_[1 .. $#_]));
  return if (not defined($sName) and not defined($paList));

  my $paIPs;
  @$paIPs = grep {defined($_)} map {$oSelf->_cidr_ip($_)} @$paList;

  # The difference between given IPs and those that are valid - should be 0
  my $sReturn = (scalar(@$paList) - scalar(@$paIPs));

  if (not $oSelf->is_ipset($sName))
  {
    $oSelf->{ipset}{$sName} = {'list' => $paIPs};
  }
  else 
  {
    push @{$oSelf->{ipset}{$sName}{list}}, @$paIPs;
  }

  if (defined($phOpts))
  {
    foreach my $sKey (keys %$phOpts)
    {
      $oSelf->{ipset}{$sName}{$sKey} = $phOpts->{$sKey};
    }
  }

  return ($sReturn ? -$sReturn : 1);
}

=item get_set($sName)

Return an array of data appropriate for 'ipset restore'. Return only one set if a valid name was supplied or all sets if no set name was given.

=cut

sub get_ipset
{
  my ($oSelf, $sName) = @_;

  return if (defined($sName) and not $oSelf->is_ipset($sName));
  my @aIter = ($sName // keys(%{$oSelf->{ipset}}));

  my @aRet;
  foreach my $sName (@aIter)
  {
    my $phData = $oSelf->{ipset}{$sName};
    my $sType = $phData->{type} // 'hash:net';
    my $sFamily = $phData->{family} // 'inet';
    my $sHashsize = $phData->{hashsize} // 1024;
    my $sMaxelen = $phData->{maxelen} // 65536;

    push @aRet, "create $sName $sType family $sFamily hashsize $sHashsize maxelen $sMaxelen";
    push @aRet, map {"add $sName $_"} @{$phData->{list}};
  }

  push @aRet, @{$oSelf->{'set comment'}};

  return @aRet;
}

=item is_ipset($sName)

Check if an ipset exists

=cut

sub is_ipset
{
  my ($oSelf, $sName) = @_;

  return (exists($oSelf->{ipset}{$sName}) ? 1 : 0);
}

=item get_ipset_data($sName)

Return internal data for an ipset or all sets if no name was given

=cut

sub get_ipset_data
{
  my ($oSelf, $sName) = @_;

  if (not defined($sName))
  {
    return $oSelf->{ipset};
  }
  elsif ($oSelf->is_ipset($sName))
  {
    return $oSelf->{ipset}{$sName};
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
  my ($oSelf) = @_;

  my @aRet;
  foreach my $sTable ($oSelf->get_tables())
  {
    push @aRet, "*$sTable", @{$oSelf->save_table($sTable)}, "COMMIT";
  }

  push @aRet, @{$oSelf->{'nf comment'}};

  return @aRet;
}

=item get_tables()

Return a list of tables

=cut

sub get_tables
{
  my ($oSelf) = @_;

  return ($oSelf->_sortpre(
    [keys %{$oSelf->{nf}}],
    [qw/raw nat mangle filter/]
  ));
}

=item save_table($sTable)

Return an iptables-save array for all chains in a table (default to filter if no table is supplied)

=cut

sub save_table
{
  my ($oSelf, $sTable) = @_;
  $sTable //= 'filter';

  return if (not $oSelf->is_table($sTable));

  my (@aHead, @aChains);
  foreach my $sChain ($oSelf->get_chains($sTable))
  {
    push @aHead, $oSelf->get_header($sChain, $sTable);
    push @aChains, @{$oSelf->save_chain($sChain, $sTable)};
  }

  my @aRet;

  push @aRet, @aHead, @aChains;

  return [@aRet];
}

=item get_chain($sTable)

Return a list of chains for a table

=cut

sub get_chains
{
  my ($oSelf, $sTable) = @_;

  return if (not $oSelf->is_table($sTable));
  return (
    $oSelf->_sortpre(
      [keys(%{$oSelf->{nf}{$sTable}})], 
      [qw/PREROUTING INPUT FORWARD OUTPUT POSTROUTING/],
    )
  );
}

=item save_chain($sChain, $sTable)

Return an array with iptables-save data for one chain

=cut

sub save_chain
{
  my ($oSelf, $sChain, $sTable) = @_;
  $sTable //= 'filter';

  return if (not defined($sChain) and not $oSelf->is_chain($sChain, $sTable));

  my @aReturn;
  foreach my $sRule ($oSelf->get_rules($sChain, $sTable))
  {
    my @aAssembled = $oSelf->assemble($sRule);
    return if (not scalar(@aAssembled));
    push @aReturn, "-A $sChain " . join(" ", map {@$_} @{$oSelf->_expand(@aAssembled)});
  }

  return [@aReturn];
}

=item get_rules($sChain, $sTable)

Return data structure of rules in a chain

=cut

sub get_rules
{
  my ($oSelf, $sChain, $sTable) = @_;
  $sTable //= 'filter';

  return if (not $oSelf->is_chain($sChain, $sTable));
  return @{$oSelf->{nf}{$sTable}{$sChain}};
}

=item assemble(%$phParams)

Put an iptables rule for a data structure definition

=cut

sub assemble
{
  my ($oSelf, $phParams) = @_;

  my @iptparts;
  $oSelf->_each_kv($oSelf->{lookup}, 'lookup');

  while (my ($sListKey, $sComp) = $oSelf->_each_kv(undef, 'lookup'))
  {
    my $sKey = $oSelf->_return_valid_param($sListKey, $phParams);
    next if (not defined($sKey));

    my $phData = $oSelf->_param_str($sKey, $phParams->{$sKey});
    my $paRet = $oSelf->_comp($sComp, $phData);

    if (defined($paRet) and ref($paRet) eq 'ARRAY')
    {
      push @iptparts, $paRet;
    }
    else
    {
      warn "No data or invalid data type returned for " . Dumper($phData) .
        "listkey [sListKey] key [$sKey] comp [$sComp]\n";
    }
  }

  return [@iptparts];
}


1;

__END__

