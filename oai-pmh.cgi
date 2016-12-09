#!/opt/CSCperl/current/bin/perl
#
# Check the above perl location. The correct location could be something like
# #!/oracle/app/oracle/product/11.2.0/db_1/perl/bin/perl
#
# OAI-PMH repository script for Voyager
#
# Copyright (c) 2005-2016 University Of Helsinki (The National Library Of Finland)
#
# This file is part of voyager-oai-pmh-provider
#
# voyager-oai-pmh-provider is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

# Original author: Ere Maijala
# Version 2.13.6

use strict;
use warnings;
use Cwd 'abs_path';
use File::Basename qw(dirname);

# Include settings from <script_name>.config
# i.e. oai-pmh.cgi reads oai-pmh.config
my $config_file = abs_path($0);
$config_file =~ s/.cgi$/.config/;
# Override $config_file here to include a custom config name
# $config_file = '/etc/custom-oai-pmh.config';
my $config_ref = do($config_file);
die("Could not parse configuration file '$config_file': $@") if ($@ || !$config_ref);
my %config = %$config_ref;

#######################################################
# CODE
use DBI;
use IO::Socket;
use CGI qw(:standard);
use Fcntl qw 'SEEK_SET SEEK_CUR';
use Time::Local;
use Encode;
use File::stat;
use POSIX;
use Storable;

sub send_http_headers();
sub send_http_error($);
sub get_record();
sub identify();
sub list_identifiers();
sub list_metadata_formats();
sub list_sets();
sub oai_header();
sub oai_footer();
sub retrieve_records($);
sub get_attrib($$);
sub url_decode($);
sub url_encode($);
sub send_error($$);
sub create_record($$$$$$$$);
sub create_id($$);
sub id_to_rec_id($);
sub convert_to_oai_dc($$$);
sub convert_to_marcxml($$$);
sub escape_xml($);
sub keyword_search($$);
sub debug_out($$);
sub cleanup_str($);
sub check_params($);
sub check_dates($$);
sub get_record_sets($$$$$$);
sub create_sql_rules($$$$$$$$$);
sub addr_to_num($);
sub marc_to_list($);
sub list_to_marc($);
sub add_field($$$);
sub justifyrightch($$$);
sub get_field_num($$$);
sub get_subfield($$);
sub get_field_count($$);
sub get_field_subfield($$$);
sub update_subfield($$$);
sub prepend_subfield($$$);
sub update_field($$$$);
sub del_date_local_unix_time_to_oai_datetime($);
sub local_unix_time_to_oai_datetime($$);
sub oai_datetime_to_local_unix_time($);
sub oai_datetime_to_oracle_timestamp($);
sub get_linking_rules($$);
sub get_linked_records($$$);

my $request = $config{'base_url'};

my $unixtime = time();
my $timediff = timegm(gmtime($unixtime)) - timegm(localtime($unixtime));

my $global_marc_sth = undef;
my $global_mfhd_sth = undef;
my $global_mfhd_marc_sth = undef;
my $global_item_sth = undef;
my $global_item_status_sth = undef;
my $global_bib_info_sth = undef;
my $global_bib_link_sth = undef;
my $global_bib_link_bbid_sth = undef;
my %global_linking_rules = ();
my $db_tablespace = '';

my $field_start = "\x1f";
my $field_end = "\x1e";
my $record_end = "\x1d";

# MAIN ###########################
{
  my $client_addr = $ENV{'REMOTE_ADDR'} || '';
  if (scalar(@{$config{'allowed_ips'}}) > 0)
  {
    my $address_found = 0;
    my $client_addr_num = addr_to_num($client_addr);
    foreach my $address_spec (@{$config{'allowed_ips'}})
    {
      my $start_addr;
      my $end_addr;
      if (index($address_spec, '-') >= 0)
      {
        ($start_addr, $end_addr) = $address_spec =~ /(.*)-(.*)/;
      }
      else
      {
        $start_addr = $address_spec;
        $end_addr = $address_spec;
      }
      if ($client_addr_num >= addr_to_num($start_addr) && $client_addr_num <= addr_to_num($end_addr))
      {
        $address_found = 1;
        last;
      }
    }
    if (!$address_found)
    {
      send_http_error(401);
      exit 1;
    }
  }

  $ENV{'ORACLE_SID'} = $config{'ORACLE_SID'};
  $ENV{'ORACLE_HOME'} = $config{'ORACLE_HOME'};
  $config{'db_tablespace'} .= '.' if ($config{'db_tablespace'} && $config{'db_tablespace'} !~ /\.$/);
  $db_tablespace = $config{'db_tablespace'} || '';

  my $verb = param('verb');

  if (lc($verb) eq 'getrecord')
  {
    get_record();
  }
  elsif (lc($verb) eq 'identify')
  {
    identify();
  }
  elsif (lc($verb) eq 'listidentifiers')
  {
    exit 1 if (!check_params('ListIdentifiers'));
    retrieve_records($verb);
  }
  elsif (lc($verb) eq 'listmetadataformats')
  {
    list_metadata_formats();
  }
  elsif (lc($verb) eq 'listrecords')
  {
    exit 1 if (!check_params('ListRecords'));
    retrieve_records($verb);
  }
  elsif (lc($verb) eq 'listsets')
  {
    list_sets();
  }
  else
  {
    send_http_headers();
    send_error('badVerb', '');
    exit 1;
  }
}

sub send_http_headers()
{
  printf("Content-Type: text/xml\n");
  printf("\n");
}

sub get_record()
{
  return if (!check_params('GetRecord'));

  my $oai_id = param('identifier');
  my ($rec_id, $is_auth) = id_to_rec_id($oai_id);

  send_http_headers();

  if ($rec_id eq '')
  {
    send_error('idDoesNotExist', '');
    return;
  }

  my $prefix = lc(param('metadataPrefix'));
  if ($prefix ne 'oai_dc' && $prefix ne 'marc21')
  {
    send_error('cannotDisseminateFormat', '');
    return;
  }

  my $dbh = DBI->connect("dbi:Oracle:$config{'db_params'}", $config{'db_username'}, $config{'db_password'}) || die "Could not connect: $DBI::errstr";
  my $sth;
  my $marc_sth;
  if ($is_auth)
  {
    $sth = $dbh->prepare("SELECT (nvl(UPDATE_DATE, CREATE_DATE) - TO_DATE(\'01-01-1970\',\'DD-MM-YYYY\')) * 86400 as MOD_DATE from ${db_tablespace}AUTH_MASTER where AUTH_ID=?") || die $dbh->errstr;
    $marc_sth = $dbh->prepare("SELECT RECORD_SEGMENT FROM ${db_tablespace}AUTH_DATA WHERE AUTH_ID=? ORDER BY SEQNUM") || die $dbh->errstr;
  }
  else
  {
    $sth = $dbh->prepare("SELECT (nvl(UPDATE_DATE, CREATE_DATE) - TO_DATE(\'01-01-1970\',\'DD-MM-YYYY\')) * 86400 as MOD_DATE from ${db_tablespace}BIB_MASTER where BIB_ID=?") || die $dbh->errstr;
    $marc_sth = $dbh->prepare("SELECT RECORD_SEGMENT FROM ${db_tablespace}BIB_DATA WHERE BIB_ID=? ORDER BY SEQNUM") || die $dbh->errstr;
  }

  $sth->execute($rec_id) || die $dbh->errstr;
  my @row = $sth->fetchrow_array();
  my $mod_date = $row[0];
  $sth->finish();

  my $marcdata = '';
  $marc_sth->execute($rec_id) || die $dbh->errstr;
  while (my (@marcrow) = $marc_sth->fetchrow_array)
  {
    $marcdata .= $marcrow[0];
  }
  $marc_sth->finish();

  if ($marcdata eq '')
  {
    send_error('idDoesNotExist', '');
    return;
  }

  substr($marcdata, 5, 1) = 'c' if (substr($marcdata, 5, 1) eq 'd');

  my $response = oai_header();
  $response .= qq|  <request verb="GetRecord" identifier="$oai_id" metadataPrefix="$prefix">$request</request>
  <GetRecord>
    <record>
|;

  $response .= create_record($dbh, $rec_id, $mod_date, $marcdata, 'getrecord', $prefix, $is_auth, undef);

  $response .= qq|    </record>
  </GetRecord>
|;
  $response .= oai_footer();

  printf("%s", $response);

  $dbh->disconnect();
}

sub identify()
{
  return if (!check_params('Identify'));

  my $dbh = DBI->connect("dbi:Oracle:$config{'db_params'}", $config{'db_username'}, $config{'db_password'}) || die "Could not connect: $DBI::errstr";
  my $sth = $dbh->prepare("SELECT (MIN(CREATE_DATE) - TO_DATE('01-01-1970','DD-MM-YYYY')) * 86400 FROM ${db_tablespace}BIB_MASTER") || die $dbh->errstr;

  send_http_headers();

  $sth->execute() || die $dbh->errstr;
  my @row = $sth->fetchrow_array();
  my $earliest_timestamp = local_unix_time_to_oai_datetime($row[0], 1);

  my $sample_id = create_id(123, 0);
  my $response = oai_header();
  $response .= qq|  <request verb="Identify">$request</request>
  <Identify>
    <repositoryName>$config{'repository_name'}</repositoryName>
    <baseURL>$config{'base_url'}</baseURL>
    <protocolVersion>2.0</protocolVersion>
    <adminEmail>$config{'admin_email'}</adminEmail>
    <earliestDatestamp>$earliest_timestamp</earliestDatestamp>
    <deletedRecord>transient</deletedRecord>
    <granularity>YYYY-MM-DDThh:mm:ssZ</granularity>
    <compression></compression>
    <description>
      <oai-identifier
        xmlns="http://www.openarchives.org/OAI/2.0/oai-identifier"
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
        xsi:schemaLocation="http://www.openarchives.org/OAI/2.0/oai-identifier
        http://www.openarchives.org/OAI/2.0/oai-identifier.xsd">
        <scheme>oai</scheme>
        <repositoryIdentifier>$config{'repository_id'}</repositoryIdentifier>
        <delimiter>:</delimiter>
        <sampleIdentifier>$sample_id</sampleIdentifier>
      </oai-identifier>
    </description>
  </Identify>
|;
  $response .= oai_footer();
  printf("%s", $response);
}

sub list_metadata_formats()
{
  return if (!check_params('ListMetadataFormats'));

  send_http_headers();

  my $oai_id = param('identifier');
  if ($oai_id)
  {
    my ($rec_id, $is_auth) = id_to_rec_id($oai_id);

    if (!$rec_id)
    {
      send_error('idDoesNotExist', '');
      return;
    }

    my $dbh = DBI->connect("dbi:Oracle:$config{'db_params'}", $config{'db_username'}, $config{'db_password'}) || die "Could not connect: $DBI::errstr";
    my $sth;
    if ($is_auth)
    {
      $sth = $dbh->prepare("SELECT (nvl(UPDATE_DATE, CREATE_DATE) - TO_DATE(\'01-01-1970\',\'DD-MM-YYYY\')) * 86400 as MOD_DATE from ${db_tablespace}AUTH_MASTER where AUTH_ID=?") || die $dbh->errstr;
    }
    else
    {
      $sth = $dbh->prepare("SELECT (nvl(UPDATE_DATE, CREATE_DATE) - TO_DATE(\'01-01-1970\',\'DD-MM-YYYY\')) * 86400 as MOD_DATE from ${db_tablespace}BIB_MASTER where BIB_ID=?") || die $dbh->errstr;
    }

    $sth->execute($rec_id) || die $dbh->errstr;
    my $rec_found = $sth->fetchrow_array();
    $sth->finish();

    $dbh->disconnect();

    if (!$rec_found)
    {
      send_error('idDoesNotExist', '');
      return;
    }
  }

  my $response = oai_header();

  my $identifier = $oai_id ? " identifier=\"$oai_id\"" : '';

  $response .= qq|  <request verb="ListMetadataFormats"$identifier>$request</request>
  <ListMetadataFormats>
    <metadataFormat>
      <metadataPrefix>oai_dc</metadataPrefix>
      <schema>http://www.openarchives.org/OAI/2.0/oai_dc.xsd</schema>
      <metadataNamespace>http://www.openarchives.org/OAI/2.0/oai_dc/</metadataNamespace>
    </metadataFormat>
    <metadataFormat>
      <metadataPrefix>marc21</metadataPrefix>
      <schema>http://www.loc.gov/standards/marcxml/schema/MARC21slim.xsd</schema>
      <metadataNamespace>http://www.loc.gov/MARC21/slim</metadataNamespace>
    </metadataFormat>
  </ListMetadataFormats>
|;
  $response .= oai_footer();
  printf("%s", $response);
}

sub list_sets()
{
  return if (!check_params('ListSets'));

  send_http_headers();

  my @sets = @{$config{'sets'}};

  if (scalar(@sets) == 0)
  {
    send_error('noSetHierarchy', '');
  }

  my $response = oai_header();
  $response .= qq|  <request verb="ListSets">$request</request>
  <ListSets>
|;
  printf("%s", $response);

  foreach my $set (@sets)
  {
    printf("    <set>\n");
    printf("      <setSpec>%s</setSpec>\n", escape_xml($set->{'id'}));
    printf("      <setName>%s</setName>\n", escape_xml($set->{'name'}));
    printf("    </set>\n");
  }

  $response = qq|  </ListSets>
|;
  $response .= oai_footer();
  printf("%s", $response);
}

sub retrieve_records($)
{
  my ($verb) = @_;

  my $record_prefix = '';
  my $record_suffix = '';

  if (lc($verb) eq 'listrecords')
  {
    $record_prefix = "  <record>\n";
    $record_suffix = "  </record>\n";
  }

  my $from = '';
  my $until = '';
  my $set = '';
  my $prefix = '';
  my $cursor_pos = 0;
  my $token = url_decode(param('resumptionToken'));
  my $resumption = 0;
  my $deletions_pos = 0;
  my $deletions_index = 0;
  my $mfhd_deletions_pos = 0;

  debug_out("retrieve_records $verb", 0);

  if ($token)
  {
    $resumption = 1;
    $from = get_attrib($token, 'from');
    $until = get_attrib($token, 'until');
    $set = get_attrib($token, 'set');
    $prefix = get_attrib($token, 'metadataPrefix');
    $cursor_pos = get_attrib($token, 'pos');
    $deletions_pos = get_attrib($token, 'del');
    $deletions_index = get_attrib($token, 'delindex');
    $mfhd_deletions_pos = get_attrib($token, 'mdel');

    if ($prefix eq '' || ($cursor_pos eq '' && !$deletions_pos))
    {
      send_http_headers();
      send_error('badResumptionToken', '');
      return;
    }
  }
  else
  {
    $from = param('from');
    $until = param('until');
    $set = param('set');
    $prefix = lc(param('metadataPrefix'));
    if ($prefix eq '')
    {
      send_http_headers();
      send_error('badArgument', 'Missing argument metadataPrefix');
      return;
    }
  }
  $cursor_pos = 0 if (!$cursor_pos);

  if ($prefix ne 'oai_dc' && $prefix ne 'marc21')
  {
    send_http_headers();
    send_error('cannotDisseminateFormat', '');
    return;
  }

  if (!check_dates($from, $until))
  {
    send_http_headers();
    send_error('badArgument', 'Invalid datestamp');
    return;
  }

  my @sets = @{$config{'sets'}};

  my $is_auth = 0;
  my $rec_formats = '';
  my $locations = '';
  my $create_locations = '';
  my $happening_locations = '';
  my $keyword = '';
  my $filter;
  my $mfhd_callno = '';
  my $pub_places = '';
  my $languages = '';
  my $component_parts = 0;
  my $suppressed = 0;
  my $rule_operator = ' and ';
  if ($set)
  {
    my $found = 0;
    foreach my $setspec (@sets)
    {
      if ($setspec->{'id'} eq $set)
      {
        $found = 1;
        $is_auth = 1 if ($setspec->{'record_type'} && $setspec->{'record_type'} eq 'A');
        $rec_formats = $setspec->{'rec_formats'};
        $locations = $setspec->{'locations'};
        $create_locations = $setspec->{'create_locations'};
        $happening_locations = $setspec->{'happening_locations'};
        $keyword = $setspec->{'keyword'};
        $filter = $setspec->{'filter'};
        $mfhd_callno = $setspec->{'mfhd_callno'};
        $pub_places = $setspec->{'pub_places'};
        $languages = $setspec->{'languages'};
        $component_parts = $setspec->{'component_parts'};
        $suppressed = $setspec->{'suppressed'};
        $rule_operator = ' or ' if ($setspec->{'rule_operator'} && $setspec->{'rule_operator'} eq 'or');
        last;
      }
    }
    if (!$found)
    {
      send_http_headers();
      send_error('noRecordsMatch', '');
      return;
    }
  }
  elsif (!$config{'return_all_for_empty_set'})
  {
    send_http_headers();
    send_error('noRecordsMatch', '');
    return;
  }

  my $from_ts = '';
  my $from_unix = 0;
  my $until_ts = '';
  my $until_unix = 0;
  if ($from)
  {
    $from .= 'T00:00:00Z' if (length($from) == 10);
    $from_ts = oai_datetime_to_oracle_timestamp($from);
    $from_unix = oai_datetime_to_local_unix_time($from);
  }
  if ($until)
  {
    $until .= 'T23:59:59Z' if (length($until) == 10);
    $until_ts = oai_datetime_to_oracle_timestamp($until);
    $until_unix = oai_datetime_to_local_unix_time($until);
  }

  my %id_hash = ();
  if ($keyword)
  {
    keyword_search($keyword, \%id_hash);
    debug_out("Keyword matches: " . scalar(keys %id_hash), 0);
    if (scalar(keys %id_hash) == 0)
    {
      send_http_headers();
      send_error('noRecordsMatch', '');
      return;
    }
  }

  my $sql_base;
  my $inner_create_where = '';
  my $inner_update_where = '';
  my $mfhd_inner_create_where = '';
  my $mfhd_inner_update_where = '';
  my $item_inner_create_where = '';
  my $item_inner_modify_where = '';
  my $inner_where_join = ' WHERE ';
  if ($from)
  {
    $inner_create_where = "${inner_where_join}CREATE_DATE >= $from_ts";
    $inner_update_where = "${inner_where_join}UPDATE_DATE >= $from_ts";
    $mfhd_inner_create_where = "${inner_where_join}MM.CREATE_DATE >= $from_ts";
    $mfhd_inner_update_where = "${inner_where_join}MM.UPDATE_DATE >= $from_ts";
    $item_inner_create_where = "${inner_where_join}ITEM.CREATE_DATE >= $from_ts";
    $item_inner_modify_where = "${inner_where_join}ITEM.MODIFY_DATE >= $from_ts";
    $inner_where_join = ' AND ';
  }
  if ($until)
  {
    $inner_create_where .= "${inner_where_join}CREATE_DATE <= $until_ts";
    $inner_update_where .= "${inner_where_join}UPDATE_DATE <= $until_ts";
    $mfhd_inner_create_where .= "${inner_where_join}MM.CREATE_DATE <= $until_ts";
    $mfhd_inner_update_where .= "${inner_where_join}MM.UPDATE_DATE <= $until_ts";
    $item_inner_create_where .= "${inner_where_join}ITEM.CREATE_DATE <= $until_ts";
    $item_inner_modify_where .= "${inner_where_join}ITEM.MODIFY_DATE <= $until_ts";
  }
  if ($is_auth)
  {
    $sql_base = qq|
select ID, (MOD_DATE - TO_DATE('01-01-1970','DD-MM-YYYY')) * 86400 as MOD_DATE from
 (select ID, max(MOD_DATE) as MOD_DATE from (
  select AUTH_ID as ID, CREATE_DATE as MOD_DATE from ${db_tablespace}AUTH_MASTER${inner_create_where}
  union
  select AUTH_ID as ID, UPDATE_DATE as MOD_DATE from ${db_tablespace}AUTH_MASTER${inner_update_where}
 ) group by ID)
|;
  }
  else
  {
    $sql_base = qq|
select ID, (MOD_DATE - TO_DATE('01-01-1970','DD-MM-YYYY')) * 86400 as MOD_DATE from
 (select ID, max(MOD_DATE) as MOD_DATE from (
  select BIB_ID as ID, CREATE_DATE as MOD_DATE
  from ${db_tablespace}BIB_MASTER${inner_create_where}
  union
  select BIB_ID as ID, UPDATE_DATE as MOD_DATE
  from ${db_tablespace}BIB_MASTER${inner_update_where}
|;
    if ($config{'include_holdings'} != 0)
    {
      $sql_base .= qq|
  union
  select BM.BIB_ID, MM.CREATE_DATE
    from ${db_tablespace}MFHD_MASTER MM
    inner join ${db_tablespace}BIB_MFHD BM on MM.MFHD_ID=BM.MFHD_ID${mfhd_inner_create_where}
  union
  select BM.BIB_ID, MM.UPDATE_DATE
    from ${db_tablespace}MFHD_MASTER MM
    inner join ${db_tablespace}BIB_MFHD BM on MM.MFHD_ID=BM.MFHD_ID${mfhd_inner_update_where}
|;
    }
    if ($config{'include_holdings'} == 2)
    {
      $sql_base .= qq|
  union
  select BM.BIB_ID, ITEM.CREATE_DATE
    from ${db_tablespace}ITEM
    inner join ${db_tablespace}MFHD_ITEM MI on ITEM.ITEM_ID=MI.ITEM_ID
    inner join ${db_tablespace}BIB_MFHD BM on MI.MFHD_ID=BM.MFHD_ID${item_inner_create_where}
  union
  select BM.BIB_ID, ITEM.MODIFY_DATE
    from ${db_tablespace}ITEM
    inner join ${db_tablespace}MFHD_ITEM MI on ITEM.ITEM_ID=MI.ITEM_ID
    inner join ${db_tablespace}BIB_MFHD BM on MI.MFHD_ID=BM.MFHD_ID${item_inner_modify_where}
|;
    }
    $sql_base .= ') group by ID)';
  }
  my $sql_join = ' where ';
  my $sql_where = '';
  my $sql_order = ' order by MOD_DATE, ID';

  if ($from)
  {
    $sql_where .= "${sql_join}MOD_DATE >= $from_ts";
    $sql_join = ' and ';
  }
  if ($until)
  {
    $sql_where .= "${sql_join}MOD_DATE <= $until_ts";
    $sql_join = ' and ';
  }

  # Actual rules
  my $sql_where2 = create_sql_rules($rule_operator, $rec_formats, $locations, $create_locations, $happening_locations, $mfhd_callno, $pub_places, $languages, $suppressed);

  if ($sql_where2)
  {
    $sql_where .= "${sql_join}($sql_where2)";
    $sql_join = ' and ';
  }

  my $dbh = DBI->connect("dbi:Oracle:$config{'db_params'}", $config{'db_username'}, $config{'db_password'}) || die "Could not connect: $DBI::errstr";

  my $marc_sth;
  if ($is_auth)
  {
     $marc_sth = $dbh->prepare("SELECT RECORD_SEGMENT FROM ${db_tablespace}AUTH_DATA WHERE AUTH_ID=? ORDER BY SEQNUM") || die $dbh->errstr;
  }
  else
  {
     $marc_sth = $dbh->prepare("SELECT RECORD_SEGMENT FROM ${db_tablespace}BIB_DATA WHERE BIB_ID=? ORDER BY SEQNUM") || die $dbh->errstr;
  }

  my $kw_comp_sth = $dbh->prepare("SELECT '1' as Found FROM ${db_tablespace}BIB_TEXT WHERE BIB_ID=? AND SUBSTR(BIB_FORMAT, 2, 1) NOT IN ('m', 's')") || die $dbh->errstr;

  my $req_attrs = '';
  $req_attrs .= " from=\"$from\"" if ($from);
  $req_attrs .= " until=\"$until\"" if ($until);
  $req_attrs .= " metadataPrefix=\"$prefix\"";
  $req_attrs .= " set=\"$set\"" if ($set);

  my $main_tag = $verb;
  my $response = oai_header();
  $response .= qq|  <request verb="$verb"$req_attrs>$request</request>
  <$main_tag>
|;

  my $ofh = select STDOUT;
  $| = 1;
  select $ofh;

  $ofh = select STDERR;
  $| = 1;
  select $ofh;

  my $response_sent = 0;

  send_http_headers();

  my $keep_alive_time = time();
  my $count = 0;
  my $fetched = 0;

  # First find all deletions and send them...
  my $deleted_file = $is_auth ? $config{'deleted_auth_file'} : $config{'deleted_bib_file'};
  if (defined($deletions_pos) && $deletions_pos >= 0 && $deleted_file && ($from || $until))
  {
    my @deletion_files;
    # There may be a single string for deletions file, or an array for multiple files
    if (ref $deleted_file ne 'ARRAY')
    {
      @deletion_files = ($deleted_file);
    }
    else
    {
      @deletion_files = @{$deleted_file};
    }
    for (my $index = $deletions_index; $index < scalar(@deletion_files); $index++)
    {
      $deleted_file = $deletion_files[$index];
      if ($index > $deletions_index)
      {
        # Opening new file, reset position
        $deletions_pos = 0;
      }

      my $df = undef;
      if (!open($df, "<$deleted_file"))
      {
        if ($index == 0)
        {
          die("Could not open deletion file $deleted_file: $!");
        }
        else
        {
          # Don't die if optional deletions file not found
          next;
        }
      }
      debug_out("Processing deletions file $index: $deleted_file", 0);
      if ($from_unix > stat($df)->mtime) {
        debug_out("Skipping $deleted_file, it's older than the 'from' date", 0);
        close($df);
        next;
      }
      sysseek($df, $deletions_pos, SEEK_SET);
      my $del_count = 0;
      my $len;
  LOOP:
      while (my $record = read_marc_record($df, $del_count))
      {
        ++$del_count;

        # Check for keep alive time
        if (abs(time() - $keep_alive_time) > $config{'keep_alive_interval'})
        {
          if (!$response_sent)
          {
            printf("%s", $response);
            $response_sent = 1;
          }
          printf("\n");
          $keep_alive_time = time();
        }

        my $f005a = get_field($record, '005');
        my $del_date = del_date_local_unix_time_to_oai_datetime(substr($f005a, 0, 14));
        my $del_date_str = local_unix_time_to_oai_datetime($del_date, 1);
        if ((!$from || $del_date_str ge $from) && (!$until || $del_date_str le $until))
        {
          my $rec_id_del = get_field($record, '001');
          $rec_id_del =~ s/[^0-9]//g;

          debug_out("Deleted Match: rec=$rec_id_del, from=" . (defined($from) ? $from : '-') .
            ", until=" . (defined($until) ? $until : '-') .
            ", del_date=$del_date_str", 1);
          # Record deletion time matches. Can't really check other rules so just say it's deleted
          ++$count;

          if (!$response_sent)
          {
            printf("%s", $response);
            $response_sent = 1;
          }

          printf("%s%s%s", $record_prefix,
            create_record($dbh, $rec_id_del, $del_date, $record, $verb, $prefix, $is_auth, $set),
            $record_suffix);

          if ($count >= $config{'max_records'})
          {
            # Create a resumption token
            $token = url_encode(sprintf("from=%s&until=%s&set=%s&metadataPrefix=%s&pos=%d&del=%d&delindex=%d&mdel=0",
              $from ? $from : '', $until ? $until : '', $set ? $set : '', $prefix, ($cursor_pos + $fetched), sysseek($df, 0, SEEK_CUR), $index));
            printf("    <resumptionToken cursor=\"%ld\">%s</resumptionToken>\n", $cursor_pos, $token);

            debug_out("$config{'max_records'} deleted records sent, resumptionToken $token", 0);
            close($df);
            printf("  </$main_tag>\n</OAI-PMH>\n");
            return;
          }
        }
      }
      close($df);
    }
  }
  debug_out("$count deleted records sent", 0);

  my $mfhd_bib_sth = undef;
  my %deleted_mfhd_bib_ids = ();

  # Handle deleted holdings first
  # TODO: check if file age is older than 'from' and bypass
  if (defined($config{'deleted_bib_file'}) && !defined($config{'deleted_mfhd_file'}))
  {
    # Deleted MFHD file not specified, take from bib and modify
    $config{'deleted_mfhd_file'} = ();
    my @bibfiles;
    my $deleted_file = $config{'deleted_bib_file'};
    if (ref $deleted_file ne 'ARRAY')
    {
      @bibfiles = ($deleted_file);
    }
    else
    {
      @bibfiles = @{$deleted_file};
    }
    for (my $i = 0; $i < scalar(@bibfiles); $i++)
    {
      my $filename = $bibfiles[$i];
      if ($filename =~ s/\.bib\./.mfhd./g)
      {
        debug_out("Autoconfigured mfhd deletions file: $filename", 0);
        push(@{$config{'deleted_mfhd_file'}}, $filename);
      }
    }
  }
  if ($config{'include_holdings'} && !$is_auth && defined($config{'deleted_mfhd_file'}) && defined($mfhd_deletions_pos) && $mfhd_deletions_pos >= 0 && ($from || $until))
  {
    my $mfhd_bib_sth = $dbh->prepare("select (nvl(UPDATE_DATE, CREATE_DATE) - TO_DATE('01-01-1970','DD-MM-YYYY')) * 86400 as MOD_DATE from ${db_tablespace}BIB_MASTER where BIB_ID=?");

    debug_out('Building list of deleted holdings...', 0);
    my $deleted_file = $config{'deleted_mfhd_file'};
    my @deletion_files;
    # There may be a single string for deletions file, or an array for multiple files
    if (ref $deleted_file ne 'ARRAY')
    {
      @deletion_files = ($deleted_file);
    }
    else
    {
      @deletion_files = @{$deleted_file};
    }
    MFHDLOOP: for (my $index = 0; $index < scalar(@deletion_files); $index++)
    {
      $deleted_file = $deletion_files[$index];
      my $df = undef;

      if (!open($df, "<$deleted_file"))
      {
        if ($index == 0)
        {
          die("Could not open deletion file $deleted_file: $!");
        }
        else
        {
          # Don't die if optional deletions file not found
          next;
        }
      }
      debug_out("Processing MFHD deletions file $index: $deleted_file", 0);
      if ($from_unix > stat($df)->mtime) {
        debug_out("Skipping $deleted_file, it's older than the 'from' date", 0);
        close($df);
        next;
      }
      sysseek($df, $deletions_pos, SEEK_SET);
      my $del_count = 0;
      my $len;
      while (my $record = read_marc_record($df, $del_count))
      {
        ++$del_count;

        # Check for keep alive time
        if (abs(time() - $keep_alive_time) > $config{'keep_alive_interval'})
        {
          if (!$response_sent)
          {
            printf("%s", $response);
            $response_sent = 1;
          }
          printf("\n");
          $keep_alive_time = time();
        }

        my $f005a = get_field($record, '005');
        my $del_date = del_date_local_unix_time_to_oai_datetime(substr($f005a, 0, 14));
        my $del_date_str = local_unix_time_to_oai_datetime($del_date, 1);
        if ((!$from || $del_date_str ge $from) && (!$until || $del_date_str le $until))
        {
          my $rec_id_del = get_field($record, '004');
          $rec_id_del =~ s/[^0-9]//g;

          # Date matches. Now check that the record still exists and get its date
          $mfhd_bib_sth->execute($rec_id_del) || die $dbh->errstr;
          my ($rec_date) = $mfhd_bib_sth->fetchrow_array();
          $mfhd_bib_sth->finish();
          if ($rec_date)
          {
            debug_out("Deleted MFHD Match: bib=$rec_id_del, from=" . (defined($from) ? $from : '-') .
              ", until=" . (defined($until) ? $until : '-') .
              ", del_date=$del_date_str", 1);
            # Record deletion time matches. Can't really check other rules here
            $deleted_mfhd_bib_ids{$rec_id_del} = $rec_date;
            if (scalar(keys(%deleted_mfhd_bib_ids)) - $mfhd_deletions_pos >= $config{'max_records'}){
              last MFHDLOOP;
            }
          }
          else
          {
            debug_out("Deleted MFHD Match but BIB doesn't exist anymore: bib=$rec_id_del, from=" . (defined($from) ? $from : '-') .
              ", until=" . (defined($until) ? $until : '-') .
              ", del_date=$del_date_str", 1);
          }
        }
      }
      close($df);
    }
    debug_out(scalar(keys(%deleted_mfhd_bib_ids)) . ' deleted holdings found', 0);
  }
  else
  {
    $mfhd_deletions_pos = -1;
  }

  my @deleted_mfhd_bib_ids_keys = keys(%deleted_mfhd_bib_ids);

  my $fetch_records = $config{'max_records'} + 1;
  $fetch_records *= 100 if (defined($filter) || $keyword);
  while ($count < $config{'max_records'})
  {
    my $sth = undef;
    my @row = undef;
    my $found_records = 0;

    while (1)
    {
      my $rec_id = undef;
      my $rec_date = undef;

      if (defined($mfhd_deletions_pos) && $mfhd_deletions_pos >= 0 && $mfhd_deletions_pos < scalar(@deleted_mfhd_bib_ids_keys))
      {
        $rec_id = $deleted_mfhd_bib_ids_keys[$mfhd_deletions_pos++];
        $rec_date = $deleted_mfhd_bib_ids{$rec_id};
        $found_records = 1;
      }
      else
      {
        $mfhd_deletions_pos = -1;
        if (!defined($sth))
        {
          my $full_sql = "select ID, MOD_DATE from (select ROWNUM as RNUM, ID, MOD_DATE from ($sql_base$sql_where$sql_order)) where RNUM between " . ($cursor_pos + $fetched + 1) . " and " . ($cursor_pos + $fetched + $fetch_records);
          debug_out("Creating recordset from SQL query: $full_sql", 0);
          $sth = $dbh->prepare($full_sql) || die $dbh->errstr;
          $sth->execute() || die $dbh->errstr;
          debug_out('Recordset created', 0);
        }

        (@row) = $sth->fetchrow_array();
        last if (!@row);
        ++$fetched;
        $found_records = 1;
        $rec_id = $row[0];
        $rec_date = $row[1];
      }

      debug_out("retrieve_records: processing rec id $rec_id", 1);

      if (abs(time() - $keep_alive_time) > $config{'keep_alive_interval'})
      {
        if (!$response_sent)
        {
          printf("%s", $response);
          $response_sent = 1;
        }
        printf("\n");
        $keep_alive_time = time();
      }

      my $marcdata = '';

      if ($keyword && !$id_hash{$rec_id})
      {
        if (!$component_parts)
        {
          next;
        }
        elsif ($component_parts == 1)
        {
          debug_out("retrieve_records: checking if $rec_id is component...", 1);
          $kw_comp_sth->execute($rec_id) || die($dbh->errstr);
          my $found = $kw_comp_sth->fetchrow_array();
          $kw_comp_sth->finish();
          if ($found)
          {
            debug_out("retrieve_records: $rec_id is component, checking for host item...", 1);
            # Fetch MARC data first
            $marc_sth->execute($rec_id) || die $dbh->errstr;
            while (my (@marcrow) = $marc_sth->fetchrow_array())
            {
              $marcdata .= $marcrow[0];
            }
            $marc_sth->finish();

            # Check if the keyword term matches the host item of this component part
            my $host_ref = get_linked_records($dbh, $marcdata, 'HOST');
            my %host = %$host_ref;
            next if (scalar(keys %host) == 0 || !$id_hash{(keys %host)[0]});
          }
          else
          {
            next;
          }
        }
        else
        {
          next;
        }
      }
      else
      {
        $marc_sth->execute($rec_id) || die $dbh->errstr;
        while (my (@marcrow2) = $marc_sth->fetchrow_array)
        {
          $marcdata .= $marcrow2[0];
        }
        $marc_sth->finish();
      }

      if (!$response_sent)
      {
        printf("%s", $response);
        $response_sent = 1;
      }

      if (!defined($filter) || $filter->($marcdata, $rec_id, $dbh, \$marcdata))
      {
        # Deleted records shouldn't exist in the database, so make them changed instead
        substr($marcdata, 5, 1) = 'c' if (substr($marcdata, 5, 1) eq 'd');

        printf("%s%s%s", $record_prefix,
          create_record($dbh, $rec_id, $rec_date, $marcdata, $verb, $prefix, $is_auth, $set),
          $record_suffix);

        if ($component_parts && $component_parts == 2)
        {
          # Fetch all component parts for this host item
          my $component_parts_ref = get_linked_records($dbh, $marcdata, 'COMP');
          my %component_parts = %$component_parts_ref;
          foreach my $component_id (keys %component_parts)
          {
            my $comp_marcdata = '';
            $marc_sth->execute($component_id) || die $dbh->errstr;
            while (my (@marcrow3) = $marc_sth->fetchrow_array())
            {
              $comp_marcdata .= $marcrow3[0];
            }
            $marc_sth->finish();

            printf("%s%s%s", $record_prefix,
              create_record($dbh, $component_id, $component_parts{$component_id}, $comp_marcdata, $verb, $prefix, $is_auth, $set),
              $record_suffix);
            ++$count;
          }
        }
      } else {
        # Report records that don't match the filter as deleted
        substr($marcdata, 5, 1) = 'd';
        printf("%s%s%s", $record_prefix,
          create_record($dbh, $rec_id, $rec_date, $marcdata, $verb, $prefix, $is_auth, $set), $record_suffix);
      }
      last if (++$count >= $config{'max_records'});
    }
    last if (!$found_records);
    $sth->finish() if (defined($sth));
  }
  $dbh->disconnect();

  if (!$response_sent)
  {
    # No records found
    send_error('noRecordsMatch', '');
    return;
  }

  if ($count >= $config{'max_records'})
  {
    # Create a resumption token
    $token = url_encode(sprintf("from=%s&until=%s&set=%s&metadataPrefix=%s&pos=%d&del=-1&mdel=%d",
      $from ? $from : '', $until ? $until : '', $set ? $set : '', $prefix, ($cursor_pos + $fetched), $mfhd_deletions_pos));
    printf("    <resumptionToken cursor=\"%ld\">%s</resumptionToken>\n", $cursor_pos, $token);

    debug_out("$config{'max_records'} sent, resumptionToken $token", 0);
  }
  else
  {
    debug_out("$count sent", 0);
  }
  printf("  </$main_tag>\n</OAI-PMH>\n");
}

sub create_bib_text_rule($$)
{
  my ($column_name, $rule_list) = @_;

  my $bib_text_rule = '';
  my $bib_text_join = '';
  my @rules = split(/,/, $rule_list);
  # Inclusion rules
  foreach my $rule (@rules)
  {
    next if ($rule =~ /^!/);
    $bib_text_rule .= "${bib_text_join}$column_name like '$rule'";
    $bib_text_join = ' or ';
  }
  # Exclusion rules
  my $excluded_bib_text_rule = '';
  $bib_text_join = '';
  foreach my $rule (@rules)
  {
    next if ($rule !~ s/^!//);
    $excluded_bib_text_rule .= "${bib_text_join}$column_name like '$rule'";
    $bib_text_join = ' or ';
  }
  if ($excluded_bib_text_rule)
  {
    $bib_text_rule = "($bib_text_rule) and not ($excluded_bib_text_rule)";
  }
  return $bib_text_rule;
}

sub create_location_rule($$)
{
  my ($column_name, $rule_list) = @_;

  my @rules = split(/,/, $rule_list);
  # Inclusion rules
  my $inclusion = '';
  foreach my $rule (@rules)
  {
    next if ($rule =~ /^!/);
    $inclusion .= ',' if ($inclusion);
    $inclusion .= $rule;
  }
  # Exclusion rules
  my $exclusion = '';
  foreach my $rule (@rules)
  {
    next if ($rule !~ s/^!//);
    $exclusion .= ',' if ($exclusion);
    $exclusion .= $rule;
  }
  # Build the whole rule
  my $location_rule = '';
  if ($inclusion)
  {
    $location_rule = "$column_name in ($inclusion)";
  }
  if ($exclusion)
  {
    $location_rule .= ' and ' if ($location_rule);
    $location_rule .= "$column_name not in ($exclusion)";
  }
  return ($location_rule, $exclusion && !$inclusion);
}

sub create_sql_rules($$$$$$$$$)
{
  my ($rule_operator, $rec_formats, $locations, $create_locations, $happening_locations, $mfhd_callno, $pub_places, $languages, $suppressed) = @_;

  my $sql_where2 = '';
  my $sql_join2 = '';

  if ($rec_formats)
  {
    my $format_rule = create_bib_text_rule('BIB_FORMAT', $rec_formats);
    $sql_where2 .= "ID in (select BIB_ID from ${db_tablespace}BIB_TEXT where $format_rule)";
    $sql_join2 = $rule_operator;
  }

  if ($locations)
  {
    my ($location_rule, $only_exclusions) = create_location_rule('LOCATION_ID', $locations);
    $sql_where2 .= "${sql_join2}(ID in (select BM.BIB_ID from ${db_tablespace}BIB_MFHD BM inner join ${db_tablespace}MFHD_MASTER MM on MM.MFHD_ID=BM.MFHD_ID where $location_rule)";
    if ($only_exclusions)
    {
      $sql_where2 .= " OR ID not in (select BM.BIB_ID from ${db_tablespace}BIB_MFHD BM)";
    }
    $sql_where2 .= ')';
    $sql_join2 = $rule_operator;
  }

  if ($create_locations)
  {
    my ($location_rule, $only_exclusions) = create_location_rule('LOCATION_ID', $create_locations);
    $sql_where2 .= "${sql_join2}ID in (select BH.BIB_ID from ${db_tablespace}BIB_HISTORY BH where ACTION_TYPE_ID=1 AND $location_rule)";
    $sql_join2 = $rule_operator;
  }

  if ($happening_locations)
  {
    my ($location_rule, $only_exclusions) = create_location_rule('LOCATION_ID', $happening_locations);
    $sql_where2 .= "${sql_join2}ID in (select BH.BIB_ID from ${db_tablespace}BIB_HISTORY BH where $location_rule)";
    $sql_join2 = $rule_operator;
  }

  if ($mfhd_callno)
  {
    $sql_where2 .= "${sql_join2}ID in (select BIB_ID from ${db_tablespace}BIB_MFHD where MFHD_ID in (select MFHD_ID from ${db_tablespace}MFHD_MASTER where NORMALIZED_CALL_NO like '$mfhd_callno'))";
    $sql_join2 = $rule_operator;
  }

  if ($pub_places)
  {
    my $place_rule = create_bib_text_rule('PLACE_CODE', $pub_places);
    $sql_where2 .= "${sql_join2}ID in (select BIB_ID from ${db_tablespace}BIB_TEXT where $place_rule)";
    $sql_join2 = $rule_operator;
  }

  if ($languages)
  {
    my $language_rule = create_bib_text_rule('LANGUAGE', $languages);
    $sql_where2 .= "${sql_join2}ID in (select BIB_ID from ${db_tablespace}BIB_TEXT where $language_rule)";
    $sql_join2 = $rule_operator;
  }

  #if ($suppressed && $suppressed eq '0')
  #{
  #  $sql_where2 .= "${sql_join2}ID in (select BIB_ID from ${db_tablespace}BIB_MASTER where SUPPRESS_IN_OPAC='N')";
  #  $sql_join2 = $rule_operator;
  #}

  return $sql_where2;
}

sub oai_header()
{
  my $currtime = local_unix_time_to_oai_datetime($unixtime, 0);
  return qq|<?xml version="1.0" encoding="UTF-8"?>
<OAI-PMH xmlns="http://www.openarchives.org/OAI/2.0/"
   xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
   xsi:schemaLocation="http://www.openarchives.org/OAI/2.0/
   http://www.openarchives.org/OAI/2.0/OAI-PMH.xsd">
  <responseDate>$currtime</responseDate>
|;
}

sub oai_footer()
{
  return "</OAI-PMH>\n";
}

sub send_error($$)
{
  my ($error, $custom_desc) = @_;

  my $query_string = $ENV{'QUERY_STRING'};

  my %errordesc = (
    'badArgument', 'Illegal or missing argument',
    'badVerb', 'Illegal or missing verb',
    'badResumptionToken', 'Invalid resumptionToken',
    'cannotDisseminateFormat', 'Requested format not supported',
    'noRecordsMatch', 'No records found with the given arguments',
    'noSetHierarchy', 'This repository does not support sets',
    'idDoesNotExist', 'The requested ID format is invalid or the ID does not exist');

  my $desc = $errordesc{$error};
  $desc = "Unknown error $error" if (!defined($desc));

  $desc = $custom_desc if ($custom_desc);

  my ($sec, $min, $hour, $day, $mon, $year) = localtime(time());
  my $msg;
  $msg = sprintf("[%04d-%02d-%02d %02d:%02d:%02d] [error] [client: %s] OAI-PMH: %s (query: %s)",
    $year + 1900, $mon + 1, $day, $hour, $min, $sec, $ENV{'REMOTE_ADDR'}, $desc, $query_string);
  print STDERR "$msg\n";

  my $response = oai_header();
  $response .= qq|  <request>$request</request>
  <error code="$error">$desc</error>
|;
  $response .= oai_footer();
  printf("%s", $response);
}

sub send_http_error($)
{
  my ($error_code) = @_;

  my %errorname = (
    '401', 'Forbidden'
  );
  my %errordesc = (
    '401', 'Access denied'
  );

  my ($sec, $min, $hour, $day, $mon, $year) = localtime(time());
  my $msg;
#  $msg = sprintf("[%04d-%02d-%02d %02d:%02d:%02d] [error] [client: %s] OAI-PMH: Status %s %s",
#    $year + 1900, $mon + 1, $day, $hour, $min, $sec, $ENV{'REMOTE_ADDR'}, $error_code, $errorname{$error_code});
  $msg = sprintf("[error] OAI-PMH: Status %s %s", $error_code, $errorname{$error_code});
  print STDERR "$msg\n";

  printf("Status: %s %s\n", $error_code, $errorname{$error_code});
  printf("Content-type: text/plain\n");
  printf("\n");
  printf("%s\n", $errordesc{$error_code});
}

sub create_record($$$$$$$$)
{
  my ($dbh, $rec_id, $date, $marcdata, $verb, $prefix, $is_auth, $set) = @_;

  my $identifier = create_id($rec_id, $is_auth);
  my $datestamp = local_unix_time_to_oai_datetime($date, 1);
  my $deleted = substr($marcdata, 5, 1) eq 'd';

  my @setspecs = get_record_sets($dbh, $rec_id, $marcdata, $is_auth, $set, $deleted);

  # Mark record deleted if it's suppressed and set doesn't include suppressed records
  if (!$is_auth && $set && !$deleted)
  {
    my $record_suppressed = -1;
    foreach my $single_set (@{$config{'sets'}})
    {
      if ($set eq $single_set->{'id'})
      {
        if (defined($single_set->{'suppressed'}) && $single_set->{'suppressed'} == 0)
        {
          if (!defined($global_bib_info_sth))
          {
            $global_bib_info_sth = $dbh->prepare("select suppress_in_opac from ${db_tablespace}bib_master bib where bib_id=?");
          }
          $global_bib_info_sth->execute($rec_id) || die($dbh->errstr);
          my @row = $global_bib_info_sth->fetchrow_array();
          $global_bib_info_sth->finish();
          $deleted = 1 if ($row[0] eq 'Y');
        }
        last;
      }
    }
  }

  $deleted = $deleted ? ' status="deleted"' : '';
  my $str = qq|    <header$deleted>
      <identifier>$identifier</identifier>
      <datestamp>$datestamp</datestamp>
|;
  foreach my $setspec (@setspecs)
  {
    $str .= "      <setSpec>$setspec</setSpec>\n";
  }
  $str .= "    </header>\n";

  return $str if ($deleted && !$config{'return_deleted_metadata'});

  $verb = lc($verb);

  if ($verb eq 'listrecords' || $verb eq 'getrecord')
  {
    # Add holdings and availability fields
    if ($config{'include_holdings'} && !$is_auth)
    {
      if (!defined($global_mfhd_sth))
      {
        my $suppressed = '';
        if (!$config{'include_suppressed_holdings'})
        {
          $suppressed = "and MFHD_ID in (select MM.MFHD_ID from ${db_tablespace}MFHD_MASTER MM WHERE MM.MFHD_ID=BM.MFHD_ID and MM.SUPPRESS_IN_OPAC='N') AND loc.suppress_in_opac='N'";
        }
        $global_mfhd_sth = $dbh->prepare(qq|
select mfhd.mfhd_id, mfhd.suppress_in_opac, loc.location_code, loc.location_display_name, lib.library_name
  from ${db_tablespace}mfhd_master mfhd
  left outer join ${db_tablespace}location loc on (mfhd.location_id = loc.location_id)
  left outer join ${db_tablespace}library lib on (loc.library_id = lib.library_id)
  where mfhd.mfhd_id in (select bm.mfhd_id
    from ${db_tablespace}bib_mfhd bm
    where bib_id=?
    $suppressed
  )
|) || die($dbh->errstr);

        $global_mfhd_marc_sth = $dbh->prepare(qq|
select record_segment
  from ${db_tablespace}mfhd_data
  where mfhd_id=?
  order by seqnum
|) || die($dbh->errstr);

        $global_item_sth = $dbh->prepare(qq|
select item.item_id, item.historical_charges, permloc.location_display_name, temploc.location_display_name, circ.current_due_date
  from ${db_tablespace}item item
  left outer join ${db_tablespace}location permloc on (item.perm_location = permloc.location_id)
  left outer join ${db_tablespace}location temploc on (item.temp_location = temploc.location_id)
  left outer join ${db_tablespace}circ_transactions circ on (item.item_id = circ.item_id)
  where item.item_id in (select item_id from ${db_tablespace}mfhd_item mi where mi.mfhd_id = ?)
|) || die($dbh->errstr);

        $global_item_status_sth = $dbh->prepare(qq|
select its.item_status, its.item_status_date
  from ${db_tablespace}item_status its
  where its.item_id = ?
  order by its.item_status_date
|) || die($dbh->errstr);
      }

      my @biblist = marc_to_list($marcdata);
      # Delete any holdings fields from the bibliographic record (they're likely outdated)
      @biblist = delete_fields(\@biblist, '852');

      my $have_949 = 0;
      $global_mfhd_sth->execute($rec_id) || die($dbh->errstr);
      while (my (@row) = $global_mfhd_sth->fetchrow_array())
      {
        my ($mfhd_id, $mfhd_suppress, $mfhd_location_code, $mfhd_location_name, $mfhd_library) = @row;
        $mfhd_library = encode_utf8($mfhd_library);

        $global_mfhd_marc_sth->execute($mfhd_id) || die($dbh->errstr);
        my $mfhdmarc = '';
        while (my (@marc_row) = $global_mfhd_marc_sth->fetchrow_array())
        {
          $mfhdmarc .= $marc_row[0];
        }
        $global_mfhd_marc_sth->finish();
        my @mfhdlist = marc_to_list($mfhdmarc);

        foreach my $field (@mfhdlist)
        {
          @biblist = add_field(\@biblist, $field->{'code'}, $field->{'data'} . "${field_start}9$mfhd_library") if ($field->{'code'} >= 800);
        }
        if ($config{'include_holdings'} == 2)
        {

          $global_item_sth->execute($mfhd_id) || die($dbh->errstr);
          my $available = 0;
          my $unavailable = 0;
          my $historical_charges = 0;
          while (my (@item_row) = $global_item_sth->fetchrow_array())
          {
            my ($item_id, $charges) = @item_row;
            $historical_charges += $charges;

            $global_item_status_sth->execute($item_id) || die($dbh->errstr);
            while (my (@status_row) = $global_item_status_sth->fetchrow_array())
            {
              my ($status, $date) = @status_row;
              if ($status == 1 || $status == 11)
              {
                ++$available;
              }
              else
              {
                ++$unavailable;
              }
            }
            $global_item_status_sth->finish();
          }
          $global_item_sth->finish();

          if ($mfhd_suppress eq 'Y')
          {
            $unavailable += $available;
            $available = 0;
          }

          my $availability = 'check_holdings';
          if ($available > 0)
          {
            $availability = 'available';
          }
          elsif ($unavailable > 0)
          {
            $availability = 'unavailable';
          }

          my $f853_count = get_field_count($mfhdmarc, '853');
          my $multivolume = ($f853_count > 1) ? 'Y' : 'N';

          my $holdings_field = "  ${field_start}a" . encode_utf8($config{'holdings_institution_code'});
          $holdings_field .= "${field_start}b" . $mfhd_library;
          $holdings_field .= "${field_start}c" . encode_utf8($mfhd_location_name);
          $holdings_field .= "${field_start}d" . get_field_subfield($mfhdmarc, '852', 'h');
          $holdings_field .= "${field_start}e" . $availability;
          $holdings_field .= "${field_start}f" . ($available + $unavailable);
          $holdings_field .= "${field_start}g" . $unavailable;
          $holdings_field .= "${field_start}h" . $multivolume;
          $holdings_field .= "${field_start}i" . $historical_charges;
          $holdings_field .= "${field_start}j" . get_field_subfield($mfhdmarc, '852', 'b');

          @biblist = add_field(\@biblist, '949', $holdings_field);
          $have_949 = 1;
        }
      }
      $global_mfhd_sth->finish();

      if ($config{'include_holdings'} == 2 && !$have_949)
      {
        # Create 949 for no holdings
        my $holdings_field = "  ${field_start}a" . encode_utf8($config{'holdings_institution_code'});
        $holdings_field .= "${field_start}echeck_holdings";
        $holdings_field .= "${field_start}f0";
        $holdings_field .= "${field_start}g0";
        $holdings_field .= "${field_start}hN";
        $holdings_field .= "${field_start}i0";

        @biblist = add_field(\@biblist, '949', $holdings_field);
      }

      $marcdata = list_to_marc(\@biblist);
    }

    my $field773 = get_field($marcdata, '773');
    if ($field773)
    {
      # Update 773 field of component part
      my $host_ref = get_linked_records($dbh, $marcdata, 'HOST');
      my %host = %$host_ref;

      my $host_id = (keys %host)[0] if (scalar(keys %host));
      if (!$host_id)
      {
        $field773 = delete_subfield($field773, 'w');
      }
      else
      {
        my $sub_w = get_subfield($field773, 'w');
        if ($sub_w)
        {
          $field773 = update_subfield($field773, 'w', $host_id);
        }
        else
        {
          $field773 = prepend_subfield($field773, 'w', $host_id);
        }
      }
      my @biblist = marc_to_list($marcdata);
      @biblist = update_field(\@biblist, '773', 1, $field773);
      $marcdata = list_to_marc(\@biblist);
    }

    my $record;
    if ($prefix eq 'oai_dc')
    {
      $record = convert_to_oai_dc($rec_id, $marcdata, $is_auth);
    }
    elsif ($prefix eq 'marc21')
    {
      $record = convert_to_marcxml($rec_id, $marcdata, $is_auth);
    }
    $str .= sprintf("    <metadata>\n%s\n    </metadata>\n", $record);
  }
  return $str;
}

sub debug_out($$)
{
  my ($str, $verb_only) = @_;

  return if (!$config{'debug'} || ($config{'debug'} == 1 && $verb_only));

  my $query_string = $ENV{'QUERY_STRING'};

  my ($sec, $min, $hour, $day, $mon, $year) = localtime(time());
  my $msg;
  #$msg = sprintf("[%04d-%02d-%02d %02d:%02d:%02d] [debug] [client: %s] OAI-PMH: %s (query: %s)",
  #  $year + 1900, $mon + 1, $day, $hour, $min, $sec, $ENV{'REMOTE_ADDR'}, $str, $query_string);
  $msg = sprintf("[debug] OAI-PMH: %s (query: %s)", $str, $query_string);
  print STDERR "$msg\n";
}

sub local_unix_time_to_oai_datetime($$)
{
  my ($t, $adjust_tz) = @_;

  if ($adjust_tz)
  {
    # Offset by the time zone avoiding dependencies other than Time::Local
    $t += $timediff;
  }
  my ($sec, $min, $hour, $day, $mon, $year) = gmtime($t);
  my $ts = sprintf("%04d-%02d-%02dT%02d:%02d:%02dZ", $year + 1900, $mon + 1, $day, $hour, $min, $sec);

  return $ts;
}

sub oai_datetime_to_oracle_timestamp($)
{
  my ($tstr) = @_;

  my ($year, $mon, $mday, $hour, $min, $sec) = $tstr =~ /(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z/;
  die ("Could not parse oai datetime $tstr") if (!$year);

  # Convert string to datetime
  --$mon;
  $year -= 1900;
  my $time = timegm($sec, $min, $hour, $mday, $mon, $year);

  # Offset by the time zone avoiding dependencies other than Time::Local
  $time -= $timediff;

  ($sec, $min, $hour, $mday, $mon, $year) = gmtime($time);

  return sprintf("TO_DATE('%04d-%02d-%02d %02d:%02d:%02d', 'yyyy-mm-dd hh24:mi:ss')",
    $year + 1900, $mon + 1, $mday, $hour, $min, $sec);
}

sub oai_datetime_to_local_unix_time($)
{
  my ($tstr) = @_;

  my ($year, $mon, $mday, $hour, $min, $sec) = $tstr =~ /(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z/;
  die ("Could not parse oai datetime $tstr") if (!$year);

  --$mon;
  $year -= 1900;
  my $time = timegm($sec, $min, $hour, $mday, $mon, $year);

  return $time;
}

sub del_date_local_unix_time_to_oai_datetime($)
{
  my ($datestr) = @_;

  my ($year, $mon, $mday, $hour, $min, $sec) = $datestr =~ /(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
  --$mon;
  $year -= 1900;

  # Default to 1980-01-01 for invalid dates
  my $date = eval { timegm($sec, $min, $hour, $mday, $mon, $year) }
    || return timegm(0, 0, 0, 1, 0, 1980);

  return $date;
}

sub get_attrib($$)
{
  my ($a_querystr, $a_attrib) = @_;

  my @arr = split(/&/, $a_querystr);
  foreach my $param (@arr)
  {
    my ($attr, $value) = $param =~ /(.*)=(.*)/;
    return url_decode($value) if ($attr eq $a_attrib);
  }
  return '';
}

sub url_decode($)
{
  my ($url) = @_;

  return '' if (!defined($url));

  $url =~ s/\+/ /g;
  $url =~ s/%([a-fA-F0-9]{2,2})/chr(hex($1))/eg;
  return $url;
}

sub url_encode($)
{
  my ($str) = @_;

  return '' if (!$str);

  $str =~ s/([^A-Za-z0-9\-])/sprintf("%%%02X", ord($1))/seg;
  $str =~ s/%20/\+/g;
  return $str;
}

sub create_id($$)
{
  my ($id, $is_auth) = @_;

  my $oai_id = "oai$config{'id_delimiter'}$config{'repository_id'}$config{'id_delimiter'}$id";
  $oai_id .= 'A' if ($is_auth);

  return $oai_id;
}

sub id_to_rec_id($)
{
  my ($id) = @_;

  my ($rec_id) = $id =~ /oai$config{'id_delimiter'}$config{'repository_id'}$config{'id_delimiter'}(.*)/;
  my $is_auth = ($rec_id =~ s/A$//) ? 1 : 0;
  return ($rec_id, $is_auth);
}

sub escape_xml($)
{
  my ($str) = @_;

  return '' if (!defined($str));

  $str =~ s/\&/\&amp;/g;
  $str =~ s/</\&lt;/g;
  $str =~ s/>/\&gt;/g;

  # Do some cleanup too
  $str =~ s/[\x00-\x08\x0B\x0C\x0E-\x1F]//g;

  return $str;
}

sub first_word($)
{
  my ($str) = @_;

  return '' if (!$str);
  my $p = index($str, ' ');
  $str = substr($str, 0, $p) if ($p >= 0);
  return $str;
}

sub create_link($)
{
  my ($id) = @_;

  my $link = $config{'link_url'};
  $link =~ s/{ID}/$id/g;
  return $link;
}

sub convert_to_oai_dc($$$)
{
  my ($a_id, $a_marcdata, $a_is_auth) = @_;

  my $fields = '';

  my $id = escape_xml(get_field($a_marcdata, '001'));
  my $title = escape_xml(get_subfield(get_field($a_marcdata, '245'), 'a'));
  my $creator = escape_xml(get_subfield(get_field($a_marcdata, '100'), 'a'));
  my $isbn = first_word(escape_xml(get_subfield(get_field($a_marcdata, '020'), 'a')));
  my $issn = escape_xml(get_subfield(get_field($a_marcdata, '022'), 'a'));

  $fields .= "<dc:title>$title</dc:title>\n" if ($title ne '');
  $fields .= "<dc:creator>$creator</dc:creator>\n" if ($creator ne '');
  $fields .= "<dc:identifier>$id</dc:identifier>\n" if ($id ne '');
  $fields .= "<dc:identifier>urn:isbn:$isbn</dc:identifier>\n" if ($isbn ne '');
  $fields .= "<dc:identifier>urn:issn:$issn</dc:identifier>\n" if ($issn ne '');
  $fields .= '<dc:identifier>' . escape_xml(create_link($a_id)) . "</dc:identifier>\n" if ($config{'create_links'} && !$a_is_auth);

  my @subjects = get_all_fields($a_marcdata, '650');
  foreach my $subject (@subjects)
  {
    my $subject_a = escape_xml(get_subfield($subject, 'a'));
    $fields .= "<dc:subject>$subject_a</dc:subject>\n" if ($subject_a ne '');
  }

  my $str = qq|      <oai_dc:dc
          xmlns:oai_dc="http://www.openarchives.org/OAI/2.0/oai_dc/"
          xmlns:dc="http://purl.org/dc/elements/1.1/"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://www.openarchives.org/OAI/2.0/oai_dc/
          http://www.openarchives.org/OAI/2.0/oai_dc.xsd">
$fields      </oai_dc:dc>|;

  return $str;
}

sub convert_to_marcxml($$$)
{
  my ($a_id, $a_marc, $a_is_auth) = @_;

  my $leader = cleanup_str(substr($a_marc, 0, 24));
  # Fix the last character of leader
  $leader = substr($leader, 0, 23) . '0';

  my $fields = '<leader>' . escape_xml($leader) . "</leader>\n";

  my $link_field_created = ($config{'create_links'} && !$a_is_auth) ? 0 : 1;
  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  field: while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    my $field_code = substr($a_marc, $dirpos, 3);
    my $len = substr($a_marc, $dirpos + 3, 4);
    my $pos = substr($a_marc, $dirpos + 7, 5);

    $dirpos += 12;

    # Check if the field should be stripped
    foreach my $strip (@{$config{'strip_fields'}})
    {
      $strip =~ s/#/./g;
      next field if ($field_code =~ /^$strip$/);
    }

    if ($field_code < 10)
    {
      my $field = escape_xml(substr($a_marc, $base + $pos, $len));
      $field =~ s/\x1e$//g;
      $fields .= "<controlfield tag=\"$field_code\">$field</controlfield>\n";
    }
    else
    {
      if ($field_code > 856 && !$link_field_created)
      {
        # Add 856 pointing to the original record
        $fields .= '<datafield tag="856" ind1=" " ind2=" "><subfield code="u">' .
          escape_xml(create_link($a_id)) . '</subfield></datafield>';
        $link_field_created = 1;
      }
      my $ind1 = substr($a_marc, $base + $pos, 1);
      my $ind2 = substr($a_marc, $base + $pos + 1, 1);
      my $field_contents = substr($a_marc, $base + $pos + 2, $len - 2);
      my $new_field = "<datafield tag=\"$field_code\" ind1=\"$ind1\" ind2=\"$ind2\">\n";

      my @subfields = split(/[\x1e\x1f]/, $field_contents);
      my $have_subfields = 0;
      subfield: foreach my $subfield (@subfields)
      {
        my $subfield_code = escape_xml(substr($subfield, 0, 1));
        next if ($subfield_code eq '');

        # Check if the subfield should be stripped
        foreach my $strip2 (@{$config{'strip_fields'}})
        {
          next subfield if ($field_code eq substr($strip2, 0, 3) && index(substr($strip2, 3), $subfield_code) >= 0);
        }

        my $subfield_data = escape_xml(substr($subfield, 1, length($subfield)));
        if ($subfield_data ne '')
        {
          $new_field .= "  <subfield code=\"$subfield_code\">$subfield_data</subfield>\n";
          $have_subfields = 1;
        }
      }
      $new_field .= "</datafield>\n";

      $fields .= $new_field if ($have_subfields);
    }
  }
  if (!$link_field_created)
  {
    # Add 856 pointing to the original record
    $fields .= '<datafield tag="856" ind1=" " ind2=" "><subfield code="u">' .
      escape_xml(create_link($a_id)) . '</subfield></datafield>';
  }

  my $rectype = $a_is_auth ? 'Authority' : 'Bibliographic';

  my $str = qq|    <record xmlns="http://www.loc.gov/MARC21/slim"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="http://www.loc.gov/MARC21/slim
          http://www.loc.gov/standards/marcxml/schema/MARC21slim.xsd"
          type="$rectype">
$fields      </record>|;

  return $str;
}

sub check_keyword($$)
{
  my ($marcdata, $keyword) = @_;

  # AND(IN("ELE*","036A"),IN("ELU*","036A"))
  # OR(IN("ELE0*","036A"),IN("ELE1*","036A")

  my $rule_and = 0;
  if ($keyword =~ s/^AND\((.*)\)$/$1/)
  {
    $rule_and = 1;
  }
  else
  {
    $keyword =~ s/^OR\((.*)\)$/$1/;
  }

  # IN("ELE*","036A"),IN("ELU*","036A")

  debug_out("check_keyword: rule_and=$rule_and, keyword=$keyword", 1);

  while ($keyword =~ s/IN\("(.*?)","(.{3})(.)"\)//)
  {
    my ($term, $field, $subfield) = ($1, $2, $3);

    debug_out("check_keyword: term=$term, field=$field, subfield=$subfield", 1);

    $subfield = lc($subfield);
    my $match = 0;
    for (my $fieldnum = 1; $fieldnum <= get_field_count($marcdata, $field); ++$fieldnum)
    {
      my $fielddata = normalize(get_subfield(get_field_num($marcdata, $field, $fieldnum), $subfield));
      if ($term =~ s/\*$//)
      {
        $match = 1 if ($fielddata =~ /\b$term/i);
      }
      else
      {
        $match = 1 if ($fielddata =~ /\b$term\b/i);
      }
      debug_out("check_keyword: fielddata=$fielddata, match=$match", 1);
      last if ($match);
    }
    return 1 if ($match && !$rule_and);
    return 0 if (!$match && $rule_and);
  }
  return $rule_and ? 1 : 0;
}

sub get_record_sets($$$$$$)
{
  my ($dbh, $rec_id, $marcdata, $is_auth, $current_set, $deleted) = @_;

  $current_set = '' if (!defined($current_set));
  debug_out("get_record_sets: rec_id=$rec_id, is_auth=$is_auth, current_set=$current_set, deleted=$deleted", 1);

  my @sets = @{$config{'sets'}};

  my @setlist = ();
  push(@setlist, $current_set) if ($current_set);

  return @setlist if (scalar(@sets) < 2);

  if ($is_auth)
  {
    foreach my $set_auth (@sets)
    {
      next if ($current_set && $current_set eq $set_auth->{'id'});
      if ($set_auth->{'record_type'} && $set_auth->{'record_type'} eq 'A')
      {
        my $afilter = $set_auth->{'filter'};
        next if (!$deleted && defined($afilter) && !$afilter->($marcdata, $rec_id, $dbh));
        push(@setlist, $set_auth->{'id'});
      }
    }
  }
  else
  {
    foreach my $set (@sets)
    {
      next if ($current_set && $current_set eq $set->{'id'});
      debug_out("get_record_sets: checking set $set->{'id'}", 1);
      if (!$set->{'record_type'} || $set->{'record_type'} eq 'B')
      {
        if ($deleted)
        {
          push(@setlist, $set->{'id'});
          next;
        }
        my $host_bib_id = undef;
        my $component_parts = $set->{'component_parts'};
        if ($component_parts && substr($marcdata, 7, 1) !~ /[ms]/)
        {
          # Find host item
          my $host_ref = get_linked_records($dbh, $marcdata, 'HOST');
          my %host = %$host_ref;
          next if (scalar(keys %host) == 0);
          $host_bib_id = (keys %host)[0];
          debug_out("get_record_sets: host item for bib $rec_id: $host_bib_id", 1);
        }

        my $rule_operator = ' and ';
        $rule_operator = ' or ' if ($set->{'rule_operator'} && $set->{'rule_operator'} eq 'or');
        my $rec_formats = $set->{'rec_formats'};
        my $locations = $set->{'locations'};
        my $create_locations = $set->{'create_locations'};
        my $happening_locations = $set->{'happening_locations'};
        my $mfhd_callno = $set->{'mfhd_callno'};
        my $pub_places = $set->{'pub_places'};
        my $languages = $set->{'languages'};
        my $suppressed = $set->{'suppressed'};

        if (!defined($set->{'bib_sth'}))
        {
          my $sql_where = create_sql_rules($rule_operator, $rec_formats, $locations, $create_locations, $happening_locations, $mfhd_callno, $pub_places, $languages, $suppressed);
          debug_out("get_record_sets: $rec_id sql rules: $sql_where", 1);
          if ($sql_where)
          {
            $set->{'bib_sth'} = $dbh->prepare("select ID from (select BIB_ID as ID from ${db_tablespace}BIB_MASTER where BIB_ID=?) where $sql_where") || die $dbh->errstr;
          }
        }
        if (defined($set->{'bib_sth'}))
        {
          $set->{'bib_sth'}->execute($component_parts == 2 ? $host_bib_id : $rec_id) || die $dbh->errstr;

          my $bib_found = $set->{'bib_sth'}->fetchrow_array();
          $set->{'bib_sth'}->finish();
          next if (!$bib_found);
        }
        debug_out("get_record_sets: $rec_id passed sql rules", 1);

        my $keyword = $set->{'keyword'};
        my $filter = $set->{'filter'};

        if (defined($filter) && !$filter->($marcdata, $rec_id, $dbh))
        {
          debug_out("get_record_sets: $rec_id did not pass filter", 1);
          next;
        }
        debug_out("get_record_sets: $rec_id passed filter", 1);
        if ($keyword)
        {
          if ($component_parts == 1 && $host_bib_id)
          {
            debug_out("get_record_sets: fetching host marc $host_bib_id", 1);
            # Fetch host MARC
            my $host_marcdata = '';

            if (!defined($global_marc_sth))
            {
              $global_marc_sth = $dbh->prepare("SELECT RECORD_SEGMENT FROM ${db_tablespace}BIB_DATA WHERE BIB_ID=? ORDER BY SEQNUM") || die $dbh->errstr;
            }
            $global_marc_sth->execute($host_bib_id) || die $dbh->errstr;
            while (my (@marcrow) = $global_marc_sth->fetchrow_array)
            {
              $host_marcdata .= $marcrow[0];
            }
            $global_marc_sth->finish();
            if (!check_keyword($host_marcdata, $keyword))
            {
              debug_out("get_record_sets: did not pass check_keyword for host marc", 1);
              next;
            }
          }
          else
          {
            if (!check_keyword($marcdata, $keyword))
            {
              debug_out("get_record_sets: did not pass check_keyword", 1);
              next;
            }
          }
        }
        debug_out("get_record_sets: set $set->{'id'} passed", 1);
        push(@setlist, $set->{'id'});
      }
    }
  }

  return sort(@setlist);
}

sub key_to_id($)
{
  my ($key) = @_;
  my $id = (ord(substr($key, 0, 1)) << 24) + (ord(substr($key, 1, 1)) << 16) + (ord(substr($key, 2, 1)) << 8) + ord(substr($key, 3, 1));

  my $id_num = scalar($id & 0x7F);
  $id_num += ($id & 0x7F00) >> 1;
  $id_num += ($id & 0x7F0000) >> 2;
  $id_num += ($id & 0x7F000000) >> 3;

  return $id_num;
}

sub keyword_search($$)
{
  my ($keyword, $id_hash_ref) = @_;

  my $keysrv = IO::Socket::INET->new( Proto => 'tcp',
      PeerAddr=> $config{'keyword_host'},
      PeerPort=> $config{'keyword_port'},
      Reuse => 1, ) || die "Could not connect to keyword server: $!";

  $keysrv->autoflush(1);

  my $init = qq|[HEADER]
CO=EISI
AP=KEYWORD
VN=1.00
TO=10000
SK=
SQ=2
RQ=INIT
RC=0
[DATA]
AP=KEYWORD
VN=97.\@2.1
LAN=
RSV=N
PUB=N
Z39=N
ENCRYPT=N
DIEONIDLE=N


|;

  $init =~ s/\n/\x00/g;

  syswrite($keysrv, $init, length($init)) || die ("Could not send keysrv init request: $!");

  my $data = '';
  while ($data !~ /\x00\x00$/)
  {
      my $data_part;
      if ((my $len = sysread($keysrv, $data_part, 65535)) > 0)
      {
          $data .= $data_part;
      }
      else
      {
          die("Could not read keysrv init response. Current data: $data");
      }
  }

  my ($keyword_index) = $keyword =~ /IN\(".*?",\"([^\"]*)\"/;
  my $keyword_def = '';
  $keyword_def = "SPF=$keyword_index\nFCD=$keyword_index\n" if ($keyword_index);

  my $find = qq|[HEADER]
CO=EISI
AP=KEYWORD
VN=1.00
TO=10000
SK=
SQ=4
RQ=KEYWORD_SEARCH
RC=0
[DATA]
KSS=$keyword
MSH=9999999
$keyword_def

|;

  $find =~ s/\n/\x00/g;

  syswrite($keysrv, $find, length($find)) || die ("Could not send keysrv search request: $!");

  $data = '';
  while ($data !~ /\x00\x00$/)
  {
      my $data_part2;
      if ((my $len2 = sysread($keysrv, $data_part2, 65535)) > 0)
      {
          $data .= $data_part2;
      }
      else
      {
          die("Could not read keysrv search response. Current data: $data");
      }
  }

  my ($keys) = $data =~ /\x00SHT=([^\x00]*)/;

  for (my $i = 0; $i < length($keys); $i += 4)
  {
      $id_hash_ref->{key_to_id(substr($keys, $i, 4))} = 1;
  }
}

sub normalize($)
{
  my ($str) = @_;

  $str = uc($str);
  $str =~ s/-/ /g;
  $str =~ s/[\.\(\)\/\,]//g;
  $str =~ s/ $//g;
  return $str;
}

sub normalize_id($)
{
  my ($str) = @_;

  $str = uc($str);
  $str =~ s/-//g;
  $str =~ s/[\.\(\)\/\,_]//g;
  $str =~ s/ $//g;
  return $str;
}

sub get_field_count($$)
{
  my ($a_marc, $a_field) = @_;

  my $fieldcount = 0;
  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    if (!defined($a_field) || $a_field eq '' || substr($a_marc, $dirpos, 3) eq $a_field)
    {
      ++$fieldcount;
    }
    $dirpos += 12;
  }
  return $fieldcount;
}

sub get_field_num($$$)
{
  my ($a_marc, $a_field, $a_fieldnum) = @_;

  my $fieldnum = 0;
  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    if ($a_field eq '' || substr($a_marc, $dirpos, 3) eq $a_field)
    {
      ++$fieldnum;
      if ($fieldnum == $a_fieldnum)
      {
        my $len = substr($a_marc, $dirpos + 3, 4);
        my $pos = substr($a_marc, $dirpos + 7, 5);
        my $field = substr($a_marc, $base + $pos, $len);
        $field =~ s/\x1e$//g if (substr($a_marc, $dirpos, 3) < 10);
        return $field;
      }
    }
    $dirpos += 12;
  }
  return '';
}

sub get_field_subfield($$$)
{
  my ($a_marc, $a_field, $a_subfield) = @_;

  my $count = get_field_count($a_marc, $a_field);

  for (my $i = 1; $i <= $count; $i++)
  {
    my $field = get_field_num($a_marc, $a_field, $i);
    $field = get_subfield($field, $a_subfield);
    return $field if ($field);
  }
  return '';
}

sub get_field_all($$)
{
  my ($a_marc, $a_fieldnum) = @_;

  my $fieldnum = 0;
  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    ++$fieldnum;
    if ($fieldnum == $a_fieldnum)
    {
      my $len = substr($a_marc, $dirpos + 3, 4);
      my $pos = substr($a_marc, $dirpos + 7, 5);
      my $field = substr($a_marc, $base + $pos, $len);
      $field =~ s/\x1e$//g if (substr($a_marc, $dirpos, 3) < 10);
      return ($field, substr($a_marc, $dirpos, 3));
    }
    $dirpos += 12;
  }
  return ('', '');
}

sub get_field($$)
{
  my ($a_marc, $a_field) = @_;

  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    if (substr($a_marc, $dirpos, 3) eq $a_field)
    {
      my $len = substr($a_marc, $dirpos + 3, 4);
      my $pos = substr($a_marc, $dirpos + 7, 5);
      my $field = substr($a_marc, $base + $pos, $len);
      $field =~ s/\x1e$//g if ($a_field < 10);
      return $field;
    }
    $dirpos += 12;
  }
  return '';
}

sub get_all_fields($$)
{
  my ($a_marc, $a_field) = @_;

  my @fields;
  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    if (substr($a_marc, $dirpos, 3) eq $a_field)
    {
      my $len = substr($a_marc, $dirpos + 3, 4);
      my $pos = substr($a_marc, $dirpos + 7, 5);
      my $field = substr($a_marc, $base + $pos, $len);
      $field =~ s/\x1e$//g if ($a_field < 10);
      push (@fields, $field);
    }
    $dirpos += 12;
  }
  return @fields;
}

sub get_subfield($$)
{
  my ($a_fielddata, $a_subfield) = @_;

  if (!$a_subfield)
  {
    $a_fielddata =~ s/[\x1e\x1f]//g;
    return $a_fielddata;
  }
  my ($subfield) = $a_fielddata =~ /\x1f$a_subfield(.*?)[\x1e\x1f]/;
  return $subfield;
}

sub delete_subfield($$$)
{
  my ($a_fielddata, $a_subfield) = @_;

  $a_fielddata =~ s/\x1f$a_subfield.*?([\x1e\x1f])/$1/;
  return $a_fielddata;
}

sub update_subfield($$$)
{
  my ($a_fielddata, $a_subfield, $a_new_content) = @_;

  $a_fielddata =~ s/\x1f$a_subfield.*?([\x1e\x1f])/\x1f$a_subfield$a_new_content$1/;
  return $a_fielddata;
}

sub prepend_subfield($$$)
{
  my ($a_fielddata, $a_subfield, $a_new_content) = @_;

  $a_fielddata = substr($a_fielddata, 0, 2) . "\x1f$a_subfield$a_new_content" . substr($a_fielddata, 2);
  return $a_fielddata;
}

sub update_field($$$$)
{
  my ($a_list, $a_field, $a_occurrence, $a_new_content) = @_;

  my @newlist = ();

  my $fields = scalar(@$a_list);
  my $occurrence = 0;
  loop: for (my $i = 0; $i < $fields; $i++)
  {
    my $code = $a_list->[$i]{'code'};

    if ($code eq $a_field)
    {
      if (++$occurrence == $a_occurrence)
      {
        push(@newlist, {'code' => $code, 'data' => $a_new_content});
        next;
      }
    }
    push(@newlist, {'code' => $code, 'data' => $a_list->[$i]{'data'}});
  }
  return @newlist;
}

sub delete_fields($$)
{
  my ($a_list, $a_field) = @_;

  my @newlist = ();

  my $fields = scalar(@$a_list);
  loop: for (my $i = 0; $i < $fields; $i++)
  {
    my $code = $a_list->[$i]{'code'};

    if ($code ne $a_field)
    {
      push(@newlist, {'code' => $code, 'data' => $a_list->[$i]{'data'}});
    }
  }
  return @newlist;
}

sub cleanup_str($)
{
  my ($str) = @_;

  $str =~ s/[\x00-\x1f]/ /g;
  return $str;
}

# Check for invalid parameters
sub check_params($)
{
  my ($verb) = @_;

  # Check for duplicate parameters
  my @params = param();
  foreach my $param (@params)
  {
    my @paramlist = param($param);
    if (scalar(@paramlist) > 1)
    {
      send_http_headers();
      send_error('badArgument', 'Duplicate arguments not allowed');
      return 0;
    }
  }

  # Number of arguments excluding verb
  my $paramcount = scalar(param()) - 1;

  if ($verb eq 'GetRecord')
  {
    # Mandatory parameters, no others expected
    if (!param('identifier') || !param('metadataPrefix') || $paramcount != 2)
    {
      send_http_headers();
      send_error('badArgument', '');
      return 0;
    }
  }
  elsif ($verb eq 'Identify')
  {
    # No parameters
    if ($paramcount > 0)
    {
      send_http_headers();
      send_error('badArgument', '');
      return 0;
    }
  }
  elsif ($verb eq 'ListIdentifiers' || $verb eq 'ListRecords')
  {
    # Exclusive parameters
    if (param('resumptionToken'))
    {
      if ($paramcount > 1)
      {
        send_http_headers();
        send_error('badArgument', '');
        return 0;
      }
    }
    else
    {
      # Mandatory parameters
      if (!param('metadataPrefix'))
      {
        send_http_headers();
        send_error('badArgument', 'Missing argument \'metadataPrefix\'');
        return 0;
      }
      # Optional parameters
      foreach my $opt_param (@params)
      {
        if ($opt_param !~ /^(verb|from|until|set|metadataPrefix)$/i)
        {
          send_http_headers();
          send_error('badArgument', 'Illegal argument');
          return 0;
        }
      }
    }
  }
  elsif ($verb eq 'ListMetadataFormats')
  {
    # Optional parameter 'identifier', no others expected
    if ($paramcount > 1 || ($paramcount == 1 && !param('identifier')))
    {
      send_http_headers();
      send_error('badArgument', '');
      return 0;
    }
  }
  elsif ($verb eq 'ListSets')
  {
    # Only valid parameter is 'resumptionToken', but we don't use it
    if ($paramcount > 1 || ($paramcount == 1 && !param('resumptionToken')))
    {
      send_http_headers();
      send_error('badArgument', '');
      return 0;
    }
    elsif (param('resumptionToken'))
    {
      send_http_headers();
      send_error('badResumptionToken', '');
      return 0;
    }
  }
  else
  {
    die("Internal error: check_params: invalid verb: $verb");
  }
  return 1;
}

sub get_date_type($)
{
  my ($datestr) = @_;

  return 0 if (!$datestr);
  return 1 if ($datestr =~ /^\d{4}-\d{2}-\d{2}$/);
  return 2 if ($datestr =~ /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
  return 3;
}

sub check_dates($$)
{
  my ($from, $until) = @_;

  my $from_type = get_date_type($from);
  my $until_type = get_date_type($until);

  #out("check_dates: from=$from, from_type=$from_type, until=$until, until_type=$until_type", 1);

  # Invalid dates
  return 0 if ($from_type == 3 || $until_type == 3);

  # Incompatible dates
  return 0 if (($from_type == 1 && $until_type == 2) || ($from_type == 2 && $until_type == 1));

  # Until before From
  return 0 if ($from && $until && $until lt $from);

  return 1;
}

# Convert IP address (with dots) to 32 bit integer
sub addr_to_num($)
{
  my ($addr) = @_;

  my ($a1, $a2, $a3, $a4);

  if ($addr =~ /(\d+)\.(\d+)\.(\d+)\.(\d+)/)
  {
    ($a1, $a2, $a3, $a4) = ($1, $2, $3, $4);
  }
  else
  {
    die("Invalid IP address $addr");
  }

  $a1 = 255 if ($a1 == 999);
  $a2 = 255 if ($a2 == 999);
  $a3 = 255 if ($a3 == 999);
  $a4 = 255 if ($a4 == 999);

  my $val = ($a1 << 24) | ($a2 << 16) | ($a3 << 8) | $a4;
  return $val;
}

sub marc_to_list($)
{
  my ($a_marc, $a_list) = @_;

  my @list = ();
  push(@list, {'code' => '000', 'data' => substr($a_marc, 0, 23)});

  my $dirpos = 24;
  my $base = substr($a_marc, 12, 5);
  while (ord(substr($a_marc, $dirpos, 1)) != 0x1e && $dirpos < length($a_marc))
  {
    my $field_code = substr($a_marc, $dirpos, 3);
    my $len = substr($a_marc, $dirpos + 3, 4);
    my $pos = substr($a_marc, $dirpos + 7, 5);

    push(@list, {'code' => $field_code, 'data' => substr($a_marc, $base + $pos, $len)});
    $dirpos += 12;
  }
  return @list;
}

sub list_to_marc($)
{
  my ($a_list) = @_;

  my $leader = '';
  my $directory = '';
  my $marcdata = '';
  my $datapos = 0;

  my $fields = scalar(@$a_list);
  for (my $i = 0; $i < $fields; $i++)
  {
    my $code = $a_list->[$i]{'code'};
    my $fielddata = $a_list->[$i]{'data'};
    if ($code eq '000')
    {
      $leader = $fielddata;
      while (length($leader) < 24)
      {
        $leader .= '0';
      }
      next;
    }

    $fielddata .= $field_end if (substr($fielddata, length($fielddata) - 1, 1) ne $field_end);

    $directory .= justifyrightch($code, 3, '0') . justifyrightch(length($fielddata), 4, '0') .
          justifyrightch($datapos, 5, '0');

    $marcdata .= $fielddata;
    $datapos += length($fielddata);
  }
  $directory .= $field_end;
  $marcdata .= $record_end;

  my $len = length($leader) + length($directory) + length($marcdata);
  my $datastart = length($leader) + length($directory);
  $leader = justifyrightch($len, 5, '0') . substr($leader, 5, 7) . justifyrightch($datastart, 5, '0') .
    substr($leader, 17, length($leader));

  return "$leader$directory$marcdata";
}

sub add_field($$$)
{
  my ($a_list, $a_field, $a_fielddata) = @_;

  my $added = 0;
  my @newlist = ();
  my $fields = scalar(@$a_list);
  die("Sanity check failed: MARC field count > 1 000 000") if ($fields > 1000000);
  for (my $i = $fields - 1; $i >= 0; $i--)
  {
    my $code = $a_list->[$i]{'code'};
    my $fielddata = $a_list->[$i]{'data'};
    if (!$added && $code lt $a_field)
    {
      unshift(@newlist, {'code' => $a_field, 'data' => $a_fielddata});
      $added = 1;
    }
    unshift(@newlist, {'code' => $code, 'data' => $fielddata});
  }
  unshift(@newlist, {'code' => $a_field, 'data' => $a_fielddata}) if (!$added);
  return @newlist;
}

sub justifyrightch($$$)
{
    my ($str, $len, $padch) = @_;

    $str = substr($str, 0, $len);
    while (length($str) < $len)
    {
        $str = $padch . $str;
    }

    return $str;
}

sub get_linking_rules($$)
{
  my ($dbh, $rule_type) = @_;

  return @{$global_linking_rules{$rule_type}} if (defined($global_linking_rules{$rule_type}));

  # Get linking rules
  my $sth = $dbh->prepare(qq|select SEARCHCODE, FIELDOVERRIDE, SUBFIELDOVERRIDE from ${db_tablespace}DUP_PROFILE_FIELDS
where DUP_PROFILE_ID = (select DUP_PROFILE_ID from ${db_tablespace}DUP_DETECTION_PROFILE where DUP_PROFILE_CODE=?) ORDER BY SEQNUM|) || die($dbh->errstr);
  $sth->execute($rule_type) || die($dbh->errstr);
  # 773w <-> 001 is built-in
  if ($rule_type eq 'HOST')
  {
    @{$global_linking_rules{$rule_type}} = ( {'code' => 'BBID', 'field' => '773', 'subfield' => 'w'} );
  }
  else
  {
    @{$global_linking_rules{$rule_type}} = ( {'code' => '773W', 'field' => '001', 'subfield' => ''} );
  }
  while (my (@row) = $sth->fetchrow_array())
  {
    my ($searchcode, $field, $subfield) = @row;
    next if (!$searchcode || !$field);

    next if ($rule_type eq 'HOST' && ($searchcode eq '001A' || $searchcode eq 'BBID') && $field eq '773' && $subfield eq 'w');
    next if ($rule_type eq 'COMP' && $searchcode eq '773W' && $field eq '001' && !$subfield);

    push(@{$global_linking_rules{$rule_type}}, { 'code' => $searchcode, 'field' => $field, 'subfield' => substr($subfield || '', 0, 1) });
  }
  $sth->finish();
  return @{$global_linking_rules{$rule_type}};
}

sub get_linked_records($$$)
{
  my ($dbh, $marc, $link_type) = @_;

  my @link_defs = get_linking_rules($dbh, $link_type);
  if (!defined($global_bib_link_sth))
  {
    $global_bib_link_sth = $dbh->prepare("select BT.BIB_ID, rtrim(BT.TITLE), (nvl(BM.UPDATE_DATE, BM.CREATE_DATE) - TO_DATE(\'01-01-1970\',\'DD-MM-YYYY\')) * 86400 as MOD_DATE from ${db_tablespace}BIB_TEXT BT, ${db_tablespace}BIB_MASTER BM where BT.BIB_ID=BM.BIB_ID AND BT.BIB_ID in (SELECT BIB_ID from ${db_tablespace}BIB_INDEX WHERE INDEX_CODE=? AND (NORMAL_HEADING=? OR NORMAL_HEADING=?))") || die($dbh->errstr);
    $global_bib_link_bbid_sth = $dbh->prepare("select BT.BIB_ID, rtrim(BT.TITLE), (nvl(BM.UPDATE_DATE, BM.CREATE_DATE) - TO_DATE(\'01-01-1970\',\'DD-MM-YYYY\')) * 86400 as MOD_DATE from ${db_tablespace}BIB_TEXT BT, ${db_tablespace}BIB_MASTER BM where BT.BIB_ID=BM.BIB_ID AND BT.BIB_ID=?") || die($dbh->errstr);
  }

  my %linked_records = ();
  foreach my $link_def (@link_defs)
  {
    my $count = get_field_count($marc, $link_def->{'field'});
    for (my $i = 1; $i <= $count; $i++)
    {
      my $field_data = get_field_num($marc, $link_def->{'field'}, $i);
      my $identifier = first_word(get_subfield($field_data, $link_def->{'subfield'}));
      next if (!$identifier);

      my $sth;
      my $normalized_identifier = normalize_id($identifier);
      if ($normalized_identifier =~ /^[1-9]\d*$/ && ($link_def->{'code'} eq '001A' || $link_def->{'code'} eq 'BBID'))
      {
        $sth = $global_bib_link_bbid_sth;
        $sth->execute($normalized_identifier) || die($dbh->errstr);
      }
      else
      {
        $sth = $global_bib_link_sth;
        $sth->execute($link_def->{'code'}, $normalized_identifier, $identifier) || die($dbh->errstr);
      }
      while (my (@row) = $sth->fetchrow_array())
      {
        $linked_records{$row[0]} = { 'title' => $row[1], 'date' => $row[2] };
        if ($link_type eq 'HOST')
        {
          # We only need one host record
          $sth->finish();
          return \%linked_records;
        }
      }
      $sth->finish();
    }
  }
  return \%linked_records;
}

sub read_marc_record($$)
{
  my ($fh, $rec_index) = @_;

  my $len = undef;
  while (sysread($fh, $len, 5) == 5) {
    my $ch;
    # Bypass any weird old style (CSV) deletions
    if (substr($len, 0, 1) eq '"' || substr($len, 0, 1) eq "\n")
    {
      last if (!sysread($fh, $ch, 1));
      next if ($ch eq "\n");
    }

    while ($len !~ /\d{5}/)
    {
      last if (!sysread($fh, $ch, 1));
      $len = substr($len, 1, 4) . $ch;
    }

    my $record;
    if (sysread($fh, $record, $len - 5) != $len - 5)
    {
      warn("Could not read record $rec_index from input file");
      next;
    }
    $record = "$len$record";

    return $record;
  }
  return '';
}
