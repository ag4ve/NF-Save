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
  my ($oSelf, $sListKey, $phParams) = @_;

  # If a key has been used in the data correctly
  my @aKey = grep {/^!?$sListKey$/i} keys %$phParams;
  if (scalar(@aKey) > 1)
  {
    warn "Multiple keys with similar names [" . 
      join("] [", @aKey) . "] - Moving on\n";
    return;
  }
  elsif (scalar(@aKey) == 0)
  {
    return;
  }
  else
  {
    return $aKey[0];
  }
}

# Return part of the rule when passed the name of the private method and a hash.
sub _param_str
{
  my ($oSelf, $sKey, $oVal) = @_;

  my $phData;
  if (ref(\$oVal) eq 'SCALAR')
  {
    $phData = {'name' => $oVal};
  }
  elsif (ref($oVal) eq 'ARRAY')
  {
    $phData = {'name' => join(' ', @$oVal)};
  }
  elsif (ref($oVal) eq 'HASH')
  {
    $phData = $oVal;
  }
  $phData->{key} = $sKey if (not defined($phData->{key}));

  return $phData;
}

sub _comp
{
  my ($oSelf, $sComp, $phData) = @_;

  $sComp = '_' . $sComp;

  if (not $oSelf->can($sComp))
  {
    warn "No method [$sComp] - skipping\n";
    return;
  }

  return $oSelf->$sComp($phData);
}

# Actually write the rule from ipt
# NOTE This should be a private function
sub _ipt_do
{
  my ($oSelf, $sRule, $sTable, $sChain, $sDo, $sNum) = @_;

  $sNum = $sNum -1 if ($sNum eq $sNum+0);

  my $sRet;
  if ($sDo eq 'A')
  {
    $sRet = 1 unless splice
      @{$oSelf->{nf}{$sTable}{$sChain}},
      scalar(@{$oSelf->{nf}{$sTable}{$sChain}}) - $sNum,
      0,
      $sRule;
  }
  elsif ($sDo eq 'I')
  {
    $sRet = 1 unless splice
      @{$oSelf->{nf}{$sTable}{$sChain}},
      $sNum,
      0,
      $sRule;
  }
  elsif ($sDo eq 'D')
  {
    $sRet = splice
      @{$oSelf->{nf}{$sTable}{$sChain}},
      $sNum,
      1;
  }
  elsif ($sDo eq 'R')
  {
    $sRet = splice
      @{$oSelf->{nf}{$sTable}{$sChain}},
      $sNum,
      1,
      $sRule;
  }

  return $sRet;
}

# Return an array of source or destination IP address strings
sub _srcdst
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
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
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
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
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
      'proto lc' => "-p",
    ], {
      'proto' => "name",
    }
  )];
}

# Return an array of owner strings
sub _owner
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
      'name bool'        => "-m owner",
      'owner %owner' => "--uid-owner",
    ], {
      'owner' => "name",
    }, [qw/
      owner
    /], {
      "owner" => $oSelf->{uids}
    }
  )];
}

# Return an array of IP address match strings or a set name
sub _list_set
{
  my ($oSelf, $phParams) = @_;

  my $sName = $phParams->{name};
  my @aRet;

  my %hDirection;
  if (ref(\$phParams->{direction}) eq 'SCALAR')
  {
    %hDirection = map {$_ => 1} split(" ", $phParams->{direction});
  }
  elsif (ref($phParams->{direction}) eq 'ARRAY')
  {
    %hDirection = map {$_ => 1} @{$phParams->{direction}};
  }
  else
  {
    warn "Direction not defined - applying filter in both directions";
    %hDirection = (
      'src' => 1,
      'dst' => 1,
    );
  }

  if (($phParams->{useipset} and $phParams->{useipset} != 0) or 
    ($oSelf->{useipset} and $oSelf->{useipset} != 0))
  {
    warn "Set [$sName] has not been defined\n" if (not $oSelf->is_ipset($sName));
    push @aRet, "-m set --match-set $sName " . join(",", sort {$b cmp $a} keys(%hDirection));
  }
  else
  {
    if (not exists($oSelf->{ipset}{$sName}{list}) and
      ref($oSelf->{ipset}{$sName}{list}) ne 'ARRAY')
    {
      warn "No list of name [$sName]\n";
      return;
    }
    my @aList = @{$oSelf->{ipset}{$sName}{list}}; 
    if (exists($hDirection{src}))
    {
      push @aRet, map {"-s $_"} @aList;
    }
    if (exists($hDirection{dst}))
    {
      push @aRet, map {"-d $_"} @aList;
    }
  }

  return [@aRet];
}

# Return an array of match strings
sub _match
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
    'name lc' => "-m",
  ])];
}

# Return an array of TCP or UDP protocol match strings
sub _tcp_udp
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
}

# Return an array of ICMP protocol match strings
sub _icmp
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, [
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
  my ($oSelf, $phParams) = @_;
  my @order = qw/NEW RELATED ESTABLISHED INVALID/;

  my @aCTState;
  if (ref($phParams->{name}) eq 'ARRAY')
  {
    @aCTState = @{$phParams->{name}};
  }
  elsif (ref(\$phParams->{name}) eq 'SCALAR')
  {
    @aCTState = split(' ', $phParams->{name});
  }

  my @aStr;
  push @aStr, "-m conntrack";
  (push @aStr, "--ctstate " . join(',', 
    map {
      my $unit = $_;
      grep {$unit eq $_} map {uc($_)} @aCTState;
    } @order))
    if (scalar(@aCTState));
  return [join(" ", @aStr)];
}

# TODO I think a burst value of 0 is allowed (useless but allowed)
# Return an array of limit strings
sub _limit
{
  my ($oSelf, $phParams) = @_;
  my @aStr;
  push @aStr, "-m limit";
  (push @aStr, "--limit " . $phParams->{limit}) 
    if ($phParams->{limit} and 
      $phParams->{limit} =~ /^[0-9]+\/(sec(ond)?|min(ute)?|hour|day)/);
  (push @aStr, "--limit-burst " . $phParams->{burst}) if($phParams->{burst});
  return [join(" ", @aStr)];
}

# Return an array of comment strings
sub _comment
{
  my ($oSelf, $phParams) = @_;

  my @aParts;
  if (ref($phParams->{name}) eq 'ARRAY' and scalar(@{$phParams->{name}}))
  {
    push @aParts, @{$phParams->{name}};
  }
  elsif (ref(\$phParams->{name}) eq 'SCALAR' and length($phParams->{name}))
  {
    push @aParts, $phParams->{name};
  }
  else
  {
    return;
  }

  return ["-m comment --comment \"" . join(" ", grep {defined($_)} @aParts) . "\""];
}

# Return an array of jump strings
sub _jump
{
  my ($oSelf, $phParams) = @_;
  return if (not defined($phParams->{name}));
  my $sJump = $phParams->{name};
  warn "Assuming wrong case for [$sJump] - matching against [" . uc($sJump) . "]\n"
    if ($sJump =~ /[a-z]/ and $sJump =~ /^(LOG|REJECT|CT|SNAT|DNAT)$/i);

  if (uc($sJump) eq 'LOG')
  {
    return [$oSelf->_str_map($phParams, [
        'name uc' => "-j",
        'prefix qq' => "--log-prefix",
        'tcp bool' => "--log-tcp-options",
        'ip bool' => "--log-ip-options",
        'uid bool' => "--log-uid",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($sJump) eq 'REJECT')
  {
    return [$oSelf->_str_map($phParams, [
        'name uc' => "-j",
        'with bool' => "--reject-with icmp-port-unreachable",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($sJump) eq 'CT')
  {
    return [$oSelf->_str_map($phParams, [
        'name uc' => "-j",
        'notrack bool' => "--notrack",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($sJump) eq 'SNAT')
  {
    return [$oSelf->_str_map($phParams, [
        'name uc' => "-j",
        'src ip' => "--to-source",
      ], undef, [qw/name/],
    )];
  }
  elsif (uc($sJump) eq 'DNAT')
  {
    return [$oSelf->_str_map($phParams, [
        'name uc' => "-j",
        'dst ip' => "--to-destination",
      ], undef, [qw/name/],
    )];
  }
  else
  {
    return [$oSelf->_str_map($phParams, [
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
  my ($oSelf, $phParams, $paMap, $phAlt, $paRequire, $phLookup) = @_;

  return if (not $oSelf->_check_type([qw/HASH ARRAY HASH ARRAY HASH/], '>', 1, 1, @_[1 .. $#_]));

  # Setup hash to make sure that all fields that are required are present
  my %hRequire = map {$_ => 0} @$paRequire;

  # Make sure results are oldered from the even map array
  $oSelf->_each_kv($paMap, 'str_map');

  my (@aRet, @aDone);
  while (my ($sMapKey, $oMapVal) = $oSelf->_each_kv(undef, 'str_map'))
  {
    my @aMaps = split(' ', $sMapKey);
    next if (not exists($aMaps[0]));
    my $sMapStr = $aMaps[0];

    my @aPossibleKeys;
    push @aPossibleKeys, $sMapStr if (defined($sMapStr) and length($sMapStr));
    push @aPossibleKeys, $phAlt->{$sMapStr} 
      if (defined($phAlt) and defined($phAlt->{$sMapStr}));

    # [Param Key] Get the actual key from the params. Eg '!destination'
    my $sPreferredKey;
    for my $sWhichKey (@aPossibleKeys)
    {
      my @aKey = grep {/$sWhichKey/} keys %$phParams;
      $sPreferredKey = $aKey[0] if (scalar(@aKey) and defined($aKey[0]));
      if (defined($sPreferredKey))
      {
        $hRequire{$aPossibleKeys[0]} = 1;
        last;
      }
    }

    next if (not defined($sPreferredKey));

    my ($sNot, $sFuncStr) = $sPreferredKey =~ /^(!)?(.*)$/;
    # TODO Not sure why we're checking @aDone here.
    push @aRet, "!" if (defined($sNot) and not grep {$sFuncStr} @aDone);
    # An index of keys that have already been processed.
    push @aDone, $sFuncStr;
    if (ref($oMapVal) eq 'HASH')
    {
      # sOrKey - possible hParam value
      foreach my $sOrKey (keys %$oMapVal)
      {
        if ($sOrKey =~ /$phParams->{$sPreferredKey}/)
        {
          push @aRet, $oMapVal->{$sOrKey};
        }
      }
    }
    elsif (ref(\$oMapVal) eq 'SCALAR')
    {
      # Modify the key based on each map option
      my $sTempRet = $phParams->{$sPreferredKey};
      foreach my $sPossibleFunc (@aMaps[1 .. $#aMaps])
      {
        $sTempRet = $oSelf->_str_map_transform($sTempRet, $sPossibleFunc, $phLookup);
      }
      if (defined($sTempRet))
      {
        push @aRet, $oMapVal if (defined($oMapVal));
        push @aRet, $sTempRet;
      }
    }
  }

  if (not grep {$_ == 0} values(%hRequire))
  {
    return join(' ', grep {defined($_) and length($_) > 0} @aRet) if (scalar(@aRet));
  }
  else
  {
    warn "Required fields not defined: [" . 
      join("] [", grep {$hRequire{$_} == 0} keys(%hRequire)) . "] " .
      Dumper($phParams) . "\n";
    return;
  }
}

# Transform data based on mapfunc
sub _str_map_transform
{
  my ($oSelf, $sData, $sMapFunc, $phLookup) = @_;

  return if (not defined($sData));

  if (defined($sMapFunc) and length($sMapFunc))
  {
    if ($sMapFunc eq 'lc')
    {
      return lc($sData);
    }
    elsif ($sMapFunc eq 'uc')
    {
      return uc($sData);
    }
    elsif ($sMapFunc eq 'qq')
    {
      return "\"" . $sData . "\"";
    }
    elsif ($sMapFunc eq 'bool')
    {
      return if (not defined($sData));
    }
    elsif ($sMapFunc eq 'ip')
    {
      return $oSelf->_cidr_ip($sData);
    }
    # Key to lookup from
    if ($sMapFunc =~ /^%(.*)/)
    {
      my $sKey = $1;
      if (not defined($phLookup))
      {
        warn "A lookup hash was wanted but not defined.\n";
        return;
      }

      if (exists($phLookup->{$sKey}{$sData}) and defined($phLookup->{$sKey}{$sData}))
      {
        return $phLookup->{$sKey}{$sData};
      }
      else
      {
        warn "[$sData] does not exist in lookup.\n" if (defined($oSelf->{trace}));
        return $sData;
      }
    }
  }
  else
  {
    return $sData;
  }
}

# Check a list of types against an array of data
# Second option is whether there can be more data than types (>) or 
# types than data (<)
sub _check_type
{
  my ($oSelf, $paTypes, $sWhichMore, $sWarn, $sAllowUndef, @aData) = @_;

  if (ref($paTypes) ne 'ARRAY')
  {
    warn "Type must be an arrayref [" . ref($paTypes) . "].\n";
    return;
  }

  $sWhichMore //= '=';
  if ($sWhichMore eq '<' and scalar(@$paTypes) > scalar(@aData))
  {
    warn "More parameters than data\n" if ($sWarn);
    return;
  }
  elsif ($sWhichMore eq '>' and scalar(@$paTypes) < scalar(@aData))
  {
    warn "More data than parameters\n" if ($sWarn);
    return;
  }
  elsif ($sWhichMore eq '=' and scalar(@$paTypes) != scalar(@aData))
  {
    warn "Number of data not equal to the number of parameters\n" if ($sWarn);
    return;
  }

  for my $i (0 .. $#{$paTypes})
  {
    return 1 if (not defined($aData[$i]));
    if (($paTypes->[$i] =~ /^(ARRAY|HASH|CODE)$/ and ref($aData[$i]) ne $paTypes->[$i]) or 
      ($paTypes->[$i] eq 'SCALAR' and ref(\$aData[$i]) ne $paTypes->[$i]) or
      ($sAllowUndef and not defined(($aData[$i]))))
    {
      warn "[$i] " . ref($aData[$i]) . " not equal to " . $paTypes->[$i] . " " . 
        Dumper($aData[$i]) . "\n" if ($sWarn);
      return;
    }
  }
  return 1;
}

# Return a valid CIDR IP address if possible or undef
sub _valid_ip
{
  my ($oSelf, $sIP) = @_;
  $sIP =~ s|/[0-9]+||;

  return (defined($sIP) and inet_aton($sIP) ? 1 : 0);
}

# Check that a base address is in the bounds of a subnet
sub _valid_cidr
{
  my ($oSelf, $sCIDR) = @_;
  return 0 if (not defined($sCIDR));

  my ($sNetwork, $sSubnet) = split("/", $sCIDR);
  return 0 if (not defined($sNetwork) or not defined($sSubnet));

  my $sInet = unpack('N', inet_aton($sNetwork));
  my $sMask = (2**32) - (2**(32-$sSubnet));

  my $sTestMask = ($sInet | $sMask);

  return ($sTestMask <= $sMask ? 1 : 0);
}

# Return a valid CIDR address
sub _cidr_ip
{
  my ($oSelf, $sIP) = @_;

  if (not $oSelf->_valid_ip($sIP))
  {
    return;
  }
  elsif ($oSelf->_valid_cidr($sIP))
  {
    return $sIP;
  }
  else
  {
    return "$sIP/32";
  }
}

# Use an array of pairs like a hash
# Can take a 'name' for a data structure and data can either be the data or 'keys' or 'values' to return all keys/values
sub _each_kv
{
  my ($oSelf, $oData, $sName) = @_;

  $oSelf->{kv} = {} if (not defined($oSelf->{kv}) or ref($oSelf->{kv}) ne 'HASH');

  $sName = (defined($sName) ? $sName : 'each_kv');

  if (defined($oData))
  {
    # Create named group
    if (ref($oData) eq 'ARRAY')
    {
      if (scalar(@$oData) % 2)
      {
        warn "Uneven array - nothing done\n";
        return 0;
      }
      else
      {
        $oSelf->{kv}{$sName} = [@$oData];
        $oSelf->{kv}{$sName . 'orig'} = [@$oData];
        return 1;
      }
    }
    # Return named keys or values
    elsif (ref(\$oData) eq 'SCALAR' and defined($oSelf->{kv}{$sName . 'orig'}))
    {
      my ($sBool, $sMatch);
      if ($oData =~ /^key[^ ]* ?(.*)/)
      {
        $sBool = 0;
        $sMatch = $1;
      }
      elsif ($oData =~ /^val[^ ]* ?(.*)/)
      {
        $sBool = 1;
        $sMatch = $1;
      }
      else
      {
        return;
      }
  
      my @aRet;
      my $raOrig = $oSelf->{kv}{$sName . 'orig'};
      for my $sNum (0 .. $#{$raOrig})
      {
        if ($sNum % 2 == $sBool)
        {
          if (length($sMatch) > 0)
          {
            my $sCmpNum = ($sBool ? $sNum - 1 : $sNum + 1);
            next if ($raOrig->[$sCmpNum] !~ /$sMatch/);
          }
          push @aRet, $raOrig->[$sNum];
        }
      }
  
      return @aRet;
    }
  }

  # Cleanup
  if (ref($oSelf->{kv}{$sName}) ne 'ARRAY' or not scalar(@{$oSelf->{kv}{$sName}}))
  {
    delete $oSelf->{kv}{$sName};
    delete $oSelf->{kv}{$sName . 'orig'};
    return;
  }

  # Return key/value pair
  my @aRet;
  push @aRet, shift @{$oSelf->{kv}{$sName}} for (1,2);

  return @aRet;
}

# Expand arrays of arrays into an array of strings for each possibility
#        +- -+ +- -+              +-              -+
#        | a | | c |       =      | ac, ad, bc, bd |
#        | b | | d |              +-              -+
#        +- -+ +- -+  
sub _expand
{
  my ($oSelf, $paSets) = @_;

  if (not @$paSets)
  {
    return [ [] ];
  }
  else
  {
    my $paFirstSet = $paSets->[0];
    my $paCross = $oSelf->_expand([ @$paSets[1 .. $#$paSets] ]);

    return [
      map {
        my $sItem = $_; 
        map { [$sItem, @$_] } @$paCross 
      } @$paFirstSet
    ];
  }
}

# Precede sort with possible presorted values from an array.
sub _sortpre
{
  my ($oSelf, $paData, $paPreSort) = @_;
  $paPreSort //= [];

  my $i = 1;
  my $phPre = (ref($paPreSort) eq 'ARRAY' and scalar(@$paPreSort) ?
    {map {$_ => $i++} @$paPreSort} : {}
  );

  return (
    sort {
      return $phPre->{$a} <=> $phPre->{$b}
        if $phPre->{$a} && $phPre->{$b};
      return -1 if $phPre->{$a};
      return +1 if $phPre->{$b};
      return $a cmp $b;
    } @$paData
  );
}


1;

__END__

