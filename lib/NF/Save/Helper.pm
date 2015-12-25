package NF::Save::Helper;

use strict;
use warnings;

use Exporter;
our @ISA = qw(Exporter);

my @aInternal = qw/
  _str_map_transform
  _compile_ret
/;

my @aModuleInit = qw/
  _add_module
  _str_map
/;

my @aAssemble = qw/
  _return_valid_param
  _param_str
  _comp
  _ipt_do
  _check_type
  _each_kv
  _expand
  _sortpre
/;

my @aLookupComp = qw/
  _srcdst
  _io_if
  _proto
  _jump
/;

my @aIPCheck = qw/
  _valid_ip
  _valid_cidr
  _cidr_ip
/;

our @EXPORT_OK = (@aInternal, @aModuleInit, @aAssemble, @aLookupComp, @aIPCheck);
our %EXPORT_TAGS = (
  'all'       => \@EXPORT_OK,
  'module'    => \@aModuleInit,
  'assemble'  => \@aAssemble,
  'comp'      => \@aLookupComp,
  'ipcheck'   => \@aIPCheck,
);

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

sub Init
{
  return @EXPORT_OK;
}

# Confirm the value of the listkey is a base of a key of the hash
sub _return_valid_param
{
  my ($oSelf, $sListKey, $phParams) = @_;

  # If a key has been used in the data correctly
  my @aKey = grep {/^!?$sListKey$/i} keys %$phParams;
  if (scalar(@aKey) > 1)
  {
    warn "Multiple keys with similar names [" .
      join("] [", @aKey) . "] - Moving on.\n";
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
    warn "No method [$sComp] - skipping.\n";
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

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'direction +req +not' => {
          'src' => "-s",
          'dst' => "-d",
        },
        'ip +req ip' => "",
      ],
      'alt' => {
        'ip' => "name",
        'direction' => 'key',
      },
      'req' => [qw/
        direction
        ip
      /],
    }
  )];
}

# Return an array of input/output interface strings
sub _io_if
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'direction +req +not' => {
          'in' => "-i",
          'out' => "-o",
        },
        'if +req' => "",
      ],
      'alt' => {
        'if' => "name",
        'direction' => "key",
      },
      'req' => [qw/
        direction
        if
      /],
    }
  )];
}

# Return an array of protocol strings
sub _proto
{
  my ($oSelf, $phParams) = @_;

  return [$oSelf->_str_map($phParams, {
      'map' => [
        'proto +not +req lc' => "-p",
      ],
      'alt' => {
        'proto' => "name",
      },
    }
  )];
}

# Return an array of jump strings
sub _jump
{
  my ($oSelf, $phParams) = @_;
  return if (not defined($phParams->{name}));
  my $sJump = $phParams->{name};
  warn "Assuming wrong case for [$sJump] - matching against [" . uc($sJump) . "].\n"
    if ($sJump =~ /[a-z]/ and $sJump =~ /^(LOG|REJECT|CT|SNAT|DNAT)$/i);

  if (uc($sJump) eq 'LOG')
  {
    return [$oSelf->_str_map($phParams, {
        'map' => [
          'name +req uc' => "-j",
          'prefix qq' => "--log-prefix",
          'tcp +bool' => "--log-tcp-options",
          'ip +bool' => "--log-ip-options",
          'uid +bool' => "--log-uid",
        ], 
      },
    )];
  }
  elsif (uc($sJump) eq 'REJECT')
  {
    return [$oSelf->_str_map($phParams, {
        'map' => [
          'name +req uc' => "-j",
          'with +bool' => "--reject-with icmp-port-unreachable",
        ],
      },
    )];
  }
  elsif (uc($sJump) eq 'CT')
  {
    return [$oSelf->_str_map($phParams, {
        'map' => [
          'name +req uc' => "-j",
          'notrack +bool' => "--notrack",
        ],
      },
    )];
  }
  elsif (uc($sJump) eq 'SNAT')
  {
    return [$oSelf->_str_map($phParams, {
        'map' => [
          'name +req uc' => "-j",
          'src ip' => "--to-source",
        ],
      },
    )];
  }
  elsif (uc($sJump) eq 'DNAT')
  {
    return [$oSelf->_str_map($phParams, {
        'map' => [
          'name +req uc' => "-j",
          'dst ip' => "--to-destination",
        ],
      },
    )];
  }
  else
  {
    return [$oSelf->_str_map($phParams, {
        'map' => [
          'name +req' => "-j",
        ],
      },
    )];
  }
}

# Insert the name and method in the right place so the rule is in the order iptables
# would present it.
# @$paLookup is an even array of ["name" => "method"] where the method should be
# private and exclude the underscore (_) here.
# @$paPre should be a list of names that should come before this module and
# @$paPost should be a list of names that should come after.
# If post isn't defined/found, the entry will come after the last pre entry found
sub _add_module
{
  my ($oSelf, $paLookup, $paPre, $paPost) = @_;

  $oSelf->_each_kv($oSelf->{lookup});

  my @aKeys = $oSelf->_each_kv('keys');

  my $sLower;
  foreach my $i (reverse(0 .. $#aKeys))
  {
    if (grep {$_ eq $aKeys[$i]} @$paPre)
    {
      $sLower = $i;
      last;
    }
  }
  return if (not defined($sLower));

  if (defined($paPost))
  {
    last if (not scalar(@$paPost));
    my $sUpper;
    foreach my $i (0 .. $#aKeys)
    {
      if (grep {$_ eq $aKeys[$i]} @$paPost)
      {
        $sUpper = $i;
        last;
      }
    }
    if (not defined($sUpper))
    {
      warn "There was an issue finding post modules.\n";
    }
    elsif ($sLower >= $sUpper)
    {
      warn "Lower [" . $aKeys[$sLower] . "] comes after Upper [" .
        $aKeys[$sUpper] . "] - might be an issue.\n";
    }
  }
  else
  {
    warn "Module [" . $paLookup->[0] . "] did not define an upper search. " .
      "An empty set should be specified.\n";
  }

  # Lookup is an even array - sLower/sUpper is an index of the keys - the value
  # needs to be doubled to be in the right place.
  return 1 unless splice
    @{$oSelf->{lookup}},
    ($sLower+1)*2,
    0,
    @$paLookup;
}

# Return a string from a definition
# Input is a hashref of the input datastructure and a definition hash.
# The definition hash must contain a data map (key: map) but may also contain:
# map: key/value array whose keys match that of params data
# - the lookup value may not contain spaces - spaces are used to 
#   designate options
# - options/attributes may be any of:
#   - +req: required field - must be explicitly or implicitly (see alt) passed
#     from params
#   - +imp: implied field - the value will always be displayed
#   - +not: field can have not (!) prepended
#   - +bool: value of map is used if the param evaluates true
#   - @<lookup> and %<lookup> and =<lookup>: see below
#   - lc and uc: upper or lower case the string
#   - qq: quote the string
#   - ip: confirm a proper IP or CIDR string and return the CIDR string
# alt: mapping of 'actual value' => 'alias'
# lookup: a hash of values to replace
# - the key must be the name of the %value or @value of the map key parameter
# - a %value defines a hash whose value will be replaced with that of the 
#   data passed from the params
# - a @value defines an array template that will be used to sort the data 
#   passed from the params
# - a =value defines a regex the param value must match against
# will not be able to pass a 'not' or '!name' key.
sub _str_map
{
  my ($oSelf, $phParams, $phData) = @_;

  return
    if (not $oSelf->_check_type([qw/HASH HASH/],
      '>', 1, 1, @_[1 .. $#_]));

  # Check hash value types and assign them variables
  return
    if (not $oSelf->_check_type([qw/ARRAY HASH HASH/],
      '<', 0, 0, @{$phData}{qw/map alt lookup/}));
  my ($paMap, $phAlt, $phLookup) =
    @{$phData}{qw/map alt lookup/};

  # Check that not is either 1 or 0
  warn "The not should be either '1' or '0' and is [" . $phParams->{'not'} . "]\n"
    if (exists($phParams->{'not'}) and not grep {$_ eq $phParams->{'not'}} ('0', '1'));

  my $sGlobalNot = 0;
  $sGlobalNot = 1
    if (exists($phParams->{'not'}) and $phParams->{'not'});

  # Make sure results are oldered from the even map array
  $oSelf->_each_kv($paMap, 'str_map');

  # Ret are elements of a string to be returned
  # Done are the keys that have been processed
  # Require are fields that are required - set 0 after processing
  my (@aRet, %hRequire);
  # Evaluate map - look at actual data later
  while (my ($sMapKey, $oMapVal) = $oSelf->_each_kv(undef, 'str_map'))
  {
    # MapVal can be an empty string
    next if (not defined($oMapVal));

    # Options for typing and modification (ie, uc/lc)
    my ($sCanNot, $sIsImp, $sIsBool, $sMapStr, @aFuncs) = (0, 0, 0, undef, ());
    {
      my @aMaps = split(' ', $sMapKey);
      next if (not exists($aMaps[0]));
      $sMapStr = $aMaps[0];
      for my $i (1 .. $#aMaps)
      {
        my $sStr = $aMaps[$i];
        if ($sStr =~ /^\+req$/)
        {
          $hRequire{$sMapStr} = 1;
        }
        elsif ($sStr =~ /^\+not$/)
        {
          $sCanNot = 1;
        }
        elsif ($sStr =~ /^\+imp$/)
        {
          $sIsImp = 1;
          $hRequire{$sMapStr} = 1;
        }
        elsif ($sStr =~ /^\+bool$/)
        {
          $sIsBool = 1;
        }
        elsif ($sStr =~ /^(lc|uc|qq|ip|[\%\&\=].+)$/)
        {
          push @aFuncs, $sStr;
        }
        else
        {
          warn "Option [$sStr] is undefined in the API for _map_str().\n";
          return;
        }
      }
    }
    warn "A bool type pre-empts function definitions in [$sMapKey].\n"
      if ($sIsBool and scalar(@aFuncs));

    # Get the actual key from the params. Eg '!destination'
    my ($sActualKey, $sWhichKey);
    {
      my @aPossibleKeys;
      # Original possible key
      push @aPossibleKeys, $sMapStr if (defined($sMapStr) and length($sMapStr));
      # Values of alternative keys
      push @aPossibleKeys, $phAlt->{$sMapStr}
        if (defined($phAlt) and defined($phAlt->{$sMapStr}));

      for my $sKey (@aPossibleKeys)
      {
        # Only possible alteration from the given key should be a not (!)
        my @aKey = grep {/^!?$sKey$/} keys %$phParams;
        if (scalar(@aKey) and defined($aKey[0]))
        {
          $sActualKey = $aKey[0];
          # A key is found (actual or alias of it) so it should be added to 'required' for a sanity check
          $sWhichKey = $sKey;
          $hRequire{$sKey} = 1;
          last;
        }
      }
    }

    # Key was not passed in params
    if (not defined($sActualKey))
    {
      # Handle implied keys
      if ($sIsImp)
      {
        if (ref(\$oMapVal) ne 'SCALAR')
        {
          warn "The map value of [$sMapStr] must be a string.\n";
          return;
        }
        push @aRet, $oSelf->_compile_ret([$sCanNot, $sGlobalNot], $oMapVal);
        $hRequire{$sMapStr} = 0;
        next;
      }
      elsif ($hRequire{$sMapStr})
      {
        warn "[$sMapStr] required.\n";
        return;
      }
      else
      {
        next;
      }
    }

    # Strip out not designation
    # FuncStr is used when determining what the key's function is
    # ActualKey is used to refer to the param data
    my ($sNot, $sFuncStr) = $sActualKey =~ /^(!)?(.*)$/;
    # Return early if a not was it is not allowed
    if (defined($sNot) and not $sCanNot)
    {
      warn "A not (!) can not be used for [$sFuncStr] - doing nothing\n";
      return;
    }
    # Apply global not if needed
    $sNot = $sGlobalNot if (not defined($sNot) and $sCanNot);

    # User input is processed by one of these blocks or not at all
    if (ref($oMapVal) eq 'HASH')
    {
      # sOrKey - possible hParam value
      foreach my $sOrKey (keys %$oMapVal)
      {
        if (ref(\$phParams->{$sActualKey}) ne 'SCALAR')
        {
          warn "Bad data in [$sActualKey] - must be a string.\n";
          return;
        }
        if ($sOrKey =~ /$phParams->{$sActualKey}/)
        {
          push @aRet, $oSelf->_compile_ret([$sNot], $oMapVal->{$sOrKey});
          $hRequire{$sMapStr} = 0;
        }
      }
    }
    elsif (ref($oMapVal) eq 'ARRAY')
    {
      warn "Map value can not be an array\n";
      return;
    }
    elsif (ref(\$oMapVal) eq 'SCALAR')
    {
      # Might be a hash or scalar
      my $oTempRet = $phParams->{$sActualKey};
      # Use and short circuit if bool type
      if ($sIsBool)
      {
        if (ref(\$oTempRet) ne 'SCALAR' or not grep {$_ eq $oTempRet} (0, 1))
        {
          warn "[$sMapStr] value must be a 1 or 0.\n";
          return;
        }
        elsif ($oTempRet)
        {
          push @aRet, $oSelf->_compile_ret([$sNot], $oMapVal);
          $hRequire{$sMapStr} = 0;
        }
        next;
      }
      # If modifications were defined, run through them
      foreach my $sPossibleFunc (@aFuncs)
      {
        $oTempRet = $oSelf->_str_map_transform($oTempRet, $sPossibleFunc, $phLookup);
      }
      if (ref(\$oTempRet) ne 'SCALAR')
      {
        warn "Must return a string - something went wrong " .
          "(possibly in _str_map_transform).\n";
        return;
      }
      push @aRet, $oSelf->_compile_ret([$sNot], $oMapVal, $oTempRet);
      $hRequire{$sMapStr} = 0;
    }
  }

  if (grep {$_ == 0} values(%hRequire))
  {
    return join(' ', grep {defined($_) and length($_) > 0} @aRet) if (scalar(@aRet));
  }
  else
  {
    warn "Required fields not defined: [" .
      join("] [", grep {$hRequire{$_} == 1} keys(%hRequire)) . "] " .
      Dumper($phParams) . "\n";
    return;
  }
}

# Transform data based on mapfunc
sub _str_map_transform
{
  my ($oSelf, $oData, $sMapFunc, $phLookup) = @_;

  return if (not defined($oData));

  if (defined($sMapFunc) and length($sMapFunc))
  {
    # Key to lookup from
    if ($sMapFunc =~ /^([%&=])(.*)/)
    {
      my ($sType, $sKey) = ($1, $2);
      if (not defined($phLookup) or not exists($phLookup->{$sKey}))
      {
        # Try to use data in the instance before failing
        if (exists($oSelf->{$sKey}))
        {
          $phLookup = $oSelf;
        }
        else
        {
          warn "A lookup hash was wanted but not defined.\n";
          return;
        }
      }

      # Lookup replace
      if ($sType eq '%' and ref(\$oData) eq 'SCALAR')
      {
        if (exists($phLookup->{$sKey}{$oData}) and defined($phLookup->{$sKey}{$oData}))
        {
          return $phLookup->{$sKey}{$oData};
        }
        else
        {
          warn "[$oData] does not exist in lookup.\n" if (defined($oSelf->{trace}));
          return $oData;
        }
      }
      # Regex match filter
      elsif ($sType eq '=' and ref(\$oData) eq 'SCALAR')
      {
        if (ref($phLookup->{$sKey}) eq 'SCALAR')
        {
          return $oData
            if ($oData =~ /$phLookup->{$sKey}/);
        }
        else
        {
          warn "No regex key for [$sKey].\n";
          return;
        }
      }
      # Process from a dispatch table
      elsif ($sType eq '&')
      {
        if (ref($phLookup->{$sKey}) eq 'CODE')
        {
          return $phLookup->{$sKey}->($oData, $sKey);
        }
        else
        {
          warn "No dispatch for [$sKey].\n";
          return;
        }
      }
    }
    elsif (ref(\$oData) eq 'SCALAR')
    {
      if ($sMapFunc eq 'lc')
      {
        return lc($oData);
      }
      elsif ($sMapFunc eq 'uc')
      {
        return uc($oData);
      }
      elsif ($sMapFunc eq 'qq')
      {
        return "\"" . $oData . "\"";
      }
      elsif ($sMapFunc eq 'ip')
      {
        return $oSelf->_cidr_ip($oData);
      }
      else
      {
        warn "Unknown option [$sMapFunc] or bad data type for: " .
          Dumper($oData) . "\n";
        return $oData;
      }
    }
  }
  else
  {
    warn "No function.\n";
    return $oData;
  }
}

# Take an arrayref of values that must be true to prepend a not (!) and a
# list of strings to append
sub _compile_ret
{
  my ($oSelf, $paCheckNot, @aData) = @_;
  my @aRet;

  # All CheckNot must be true
  push @aRet, '!'
    if (not grep {not $_} @$paCheckNot);

  for my $sData (@aData)
  {
    if (ref(\$sData) ne 'SCALAR')
    {
      warn "_compile_ret() data must be a string.\n";
      return;
    }
    push @aRet, $sData;
  }

  return @aRet;
}

# Check a list of types against an array of data
# Second option is whether there can be more data than types (>) or
# types than data (<)
# The next two parameters are boolean - whether to warn and whether to allow undef values
# Followed by an array of data
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
    warn "More parameters than data.\n" if ($sWarn);
    return;
  }
  elsif ($sWhichMore eq '>' and scalar(@$paTypes) < scalar(@aData))
  {
    warn "More data than parameters.\n" if ($sWarn);
    return;
  }
  elsif ($sWhichMore eq '=' and scalar(@$paTypes) != scalar(@aData))
  {
    warn "Number of data not equal to the number of parameters.\n" if ($sWarn);
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
        warn "Uneven array - nothing done.\n";
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

