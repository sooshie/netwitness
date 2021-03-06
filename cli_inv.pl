#!/usr/bin/perl
#
# written by mike.sconzo@netwitness.com
# I don't guarantee this works perfectly so if you find bugs, let me know. I don't do a lot (anything)
# to sanity check input.  Fameous last words... "what could go wrong?"
#
# Requires (should be in just about any base perl install): LWP::UserAgent, Getop::Std
#
# Last Update: Rui Ataide, fixing file extracting and getting rid of the mime headers like a boss
#

use Getopt::Std;
use LWP::UserAgent;
use MIME::Parser;
use strict;
use warnings;

my %opts;
my %sessions = ();
my %metas = ();
my $IPADDRESS;
my $USERNAME;
my $PASSWORD;
my $SSL = 0;
my $NUM = 10000;
my $ID1;
my $ID2;

getopts('hi:u:p:a:m:sn:tl:o:', \%opts);

#
# prints standard usage for the script
sub usage
{
  print "cli_inv.pl [options] <action data>\n";
  print "\tOPTIONS\n";
  print "\t\t-a : action to perform: query, extract, lastmeta\n";
  print "\t\t-o : output format: tree, summary, csv, normalized. OR when used in extract mode you can specify a directory\n";
  print "\t\t-m : return values for meta keys (comma seperated list)\n";
  print "\t\t-u : username (required)\n";
  print "\t\t-p : password (required)\n";
  print "\t\t-i : IP address of concentrator/broker (required)\n";
  print "\t\t-h : this help message\n";
  print "\t\t-s : use ssl to connect\n";
  print "\t\t-n : number of results to return (default 10000)\n";
  print "\t\t-t : keep last processed meta id (usful for scripting), written to .lastmeta\n";
  print "\t\t-l : last processed meta id (to start query at), useful for scrpting\n\n";
  print "\tNOTE\n";
  print "\t\t<action data> for extract should be one of the following: exe\n";
  print "\t\t<action data> for query should be a \"custom drill\"\n";
  print "\t\tnormalized output is only useful if you're returning ip.src,ip.dst,time as it will call all meta to be in \"IDS\" alert format\n";
  print "\tEXAMPLES\n";
  print "\t\t./cli_inv.pl -m \"risk.info,risk.warning,alias.host\" -u admin -p netwitness -i 192.168.1.122:50104 -a query -o tree \"risk.info exists\"\n";
  print "\t\t./cli_inv.pl -m \"alias.host\" -u admin -p netwitness -i 192.168.1.123:50105 -a query -o summary \"service=53\"\n";
  print "\t\t./cli_inv.pl -u admin -p netwitness -i 192.168.1.122:50104 -a extract exe\n";
  print "\t\t./cli_inv.pl -u admin -p netwitness -i 192.168.1.122:50104 -a extract -o \"/tmp\" exe\n";
  exit(1);
}

#
# Performs a summary info call, gets the first and last meta ids that are in the db
# those initial values can be used to scope the initial call to retreive meta data from the db
# it can also be used to retreive other information in summary about the system.
sub summaryinfo
{
  my $ssl = shift @_;

  my $ua = LWP::UserAgent->new;
  my $req;

  #print 'http://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk?msg=summary&flags=0&force-content-type=text/plain' . "\n";
  if ($ssl)
  {
    $req = HTTP::Request->new(GET => 'https://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk?msg=summary&flags=0&force-content-type=text/plain');
  }
  else
  {
    $req = HTTP::Request->new(GET => 'http://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk?msg=summary&flags=0&force-content-type=text/plain');
  }

  # Pass request to the user agent and get a response back
  my $res = $ua->request($req);

  unless ($res->is_success)
  {
    print $res->status_line . "\n";
    print "[*] summary info failed\n";
    exit(1);
  }
  
  $res->content =~ /mid1=(.*?) mid2=(.*?) /;
  #print "$1 $2\n";
  return ($1,$2);
}

#
# gets the last meta id associated with the last full session in the database
# this is used to ensure partial session information is not reported, it's also used
# in the event there is more data requested than is in "size", this will make sure 
# all of it is retreived for accuracy
sub getlastsession
{
  my $ssl = shift @_;
  my $id1 = shift @_;
  my $id2 = shift @_;

  my $ua = LWP::UserAgent->new;
  my $req;

  #print 'http://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk?msg=session&id1=' . "$id1" . '&id2=' . "$id2" . '&force-content-type=text/plain' . "\n";
  if ($ssl)
  {
    $req = HTTP::Request->new(GET => 'https://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk?msg=session&id1=' . "$id1" . '&id2=' . "$id2" . '&force-content-type=text/plain');
  }
  else
  {
    $req = HTTP::Request->new(GET => 'http://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk?msg=session&id1=' . "$id1" . '&id2=' . "$id2" . '&force-content-type=text/plain');
  }

  # Pass request to the user agent and get a response back
  my $res = $ua->request($req);

  unless ($res->is_success)
  {
    print $res->status_line . "\n";
    print "[*] session info failed\n";
    exit(1);
  }
  
  my $con = $res->content;
  $con =~ /field2:\s(.*?)\s/;
  #print "$1\n";
  return ($1);
}

#
# Extracts files given a file type, adding additional filetypes is pretty trivial
sub extractfiles
{
  my $id1 = shift @_;
  my $id2 = shift @_;
  my $ssl = shift @_;
  my $num = shift @_;
  my $ft = shift @_;
  my $output = shift @_;
  
  my $req;
  my @filetypes = split(/,/,$ft);
  my $ua = LWP::UserAgent->new;
  
  foreach my $type (@filetypes)
  {
    $type =~ s/\s+//g;
    if ($type eq 'exe')
    {
      # return the session ids for extraction
      query($id1,$id2,$ssl,$num,'filetype=windows executable','sessionid');
      foreach my $session (keys %sessions)
      {
        if ($ssl)
      {
        $req = HTTP::Request->new(GET => 'https://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk/content?session=' . "$session" . '&render=files&includeFileType=".exe"');
      }
      else
      {
        $req = HTTP::Request->new(GET => 'http://' . "$USERNAME:$PASSWORD\@$IPADDRESS" . '/sdk/content?session=' . "$session" . '&render=files&includeFileType=".exe"');
      }
      
      # Pass request to the user agent and get a response back
      my $res = $ua->request($req);
      
      unless ($res->is_success)
      {
        print $res->status_line . "\n";
        print "[*] exe extraction failed on session: $session\n";
        exit(1);
      }
      print "Writing $session" . "._exe\n";
      
      ### Create a new parser object:
      my $parser = new MIME::Parser;
      
      ### Tell it where to put things:
      my $directory = "./" . $session;
      if ($output) {
        $directory = $output ."/" . $session;
      }
      -e $directory or mkdir $directory;
      $parser->output_dir($directory);
      
      ### Change how nameless message-component files are named:
      $parser->output_prefix("tmp");
      
      my $headers = $res->headers;
      my $mime_container = $headers->as_string . $res->content;
      
      ### Parse an input data:
      $parser->parse_data($mime_container);
      
      #open(OUT, ">$output/" .  "$session" . "._xe");
      #binmode(OUT);
      #print OUT $res->content;
      #close(OUT);
      }
    }
  }
}

#
# performs the actual query for metadata. 
sub query
{
  my $id1 = shift @_;
  my $id2 = shift @_;
  my $ssl = shift @_;
  my $num = shift @_;
  my $query = shift @_;
  my $meta = shift @_;
  
  my $url;
  my $idmax = 0;

  $meta =~ s/ +//g;
  $query =~ s/ +/\+/g;
  $query =~ s/\&/%26/g;
  $query =~ s/\|/%7C/g;
  
  $id2 = getlastsession($ssl,$id1,$id2);
  
  if ($opts{t})
  {
    open(OUT, ">.lastmeta");
    print OUT "$id2";
    close(OUT);
  }
  
  while ($idmax <= ($id2 - $num))
  {
    if ($ssl)
    {
      $url = "https://$USERNAME:$PASSWORD\@$IPADDRESS/sdk?msg=query";
    }
    else
    {
      $url = "http://$USERNAME:$PASSWORD\@$IPADDRESS/sdk?msg=query";
    }
    
    $url .= "&id1=$id1";
    $url .= "&id2=$id2";
    $url .= "&query=select+$meta+where+$query";
    $url .= "&size=$NUM&force-content-type=text/plain";
    
    #print "$url\n";
    
    my $ua = LWP::UserAgent->new;
    my $req = HTTP::Request->new(GET => "$url");
    
    # Pass request to the user agent and get a response back
    my $res = $ua->request($req);
    
    unless ($res->is_success)
    {
      print $res->status_line . "\n";
      print "[*] meta query failed\n";
      exit(1);
    }
    
    #print $res->content . "\n";
    $idmax = parseresults($res->content);
    $id1 = $idmax;
    #print "$idmax $id2\n";
  }
}

#
# parses the results and puts the data in several hash data structures
sub parseresults
{
  my $content = shift @_;
  
  my $id1max;
  
  my @results = split(/\n/,$content);
  foreach my $row (@results)
  {
    $row =~ s/(?:\n|\r)//g;
    if ($row =~ /^\[/)
    {
    ($id1max) = $row =~ /id1=(.*?)\s/;
    }
    else
    {
      my ($value,$type,$group) = $row =~ /value=(.*?)\s+type=(.*?)\s.*?group=(.*)/;
      if ($value ne '' && $type ne '' && $group ne '')
      {
        #print "$value $type $group\n";
        $sessions{$group}{$type}{$value} = 1;
        $metas{$type}{$value}{$group} = 1;
      }
    }	
  }
  return $id1max;
}

#
# prints the data in the hashes in a directory/tree like format
sub printtreeresults
{
  my $totalsessions = 0;
  
  foreach my $session (keys %sessions)
  {
    $totalsessions++;
  }
  
  foreach my $m (keys %metas)
  {
    print "Key: $m\n";
    foreach my $v (keys %{$metas{$m}})
    {
      print "    |---->$v\n";
      my $count = 0;
      foreach my $g (keys %{$metas{$m}{$v}})
      {
        #print "$v $g\n";
        print "    |     |---->$g\n";
        $count++;
      }
      print "    |\n";
      #print "$count)\n";
    }
  }
}

#
# prints summary information about the data
sub printsummaryresults
{
  my $totalsessions = 0;
  
  foreach my $session (keys %sessions)
  {
    $totalsessions++;
  }
  
  foreach my $m (keys %metas)
  {
    print "Key: $m\n";
    foreach my $v (keys %{$metas{$m}})
    {
      print "\t$v - (";
      my $count = 0;
      foreach my $g (keys %{$metas{$m}{$v}})
      {
        #print "$v $g\n";
      	$count++;
      }
      print "$count)\n";
    }
  }
}

sub printcsv
{
  print "session,meta,value\n";
  foreach my $session (keys %sessions)
  {
    foreach my $meta (keys %{$sessions{$session}})
    {
      foreach my $value (keys %{$sessions{$session}{$meta}})
      {
        print "$session,$meta,$value\n";
      }
    }
  }
}

sub printnormalized
{
  foreach my $session (keys %sessions)
  {
    foreach my $meta (keys %{$sessions{$session}})
    {
      if ($meta ne 'ip.src' && $meta ne 'ip.dst' && $meta ne 'time')
      {
        foreach my $value (keys %{$sessions{$session}{$meta}})
      	{
      	  foreach my $srcip (%{$sessions{$session}{'ip.src'}})
      	  {
      	    foreach my $dstip (%{$sessions{$session}{'ip.dst'}})
      	    {
      	      foreach my $timestamp (%{$sessions{$session}{'time'}})
      	      {
      	      	#this is a hack, don't judge me, but fix if if you know a better way
      	      	if ($srcip != 1 && $dstip != 1 && $timestamp != 1)
      	      	{
      	          print "$session,$timestamp,$value,$srcip,$dstip\n";
      	      	}
      	      }
      	    }
      	  }
      	}
      }
    }
  }
}

############
############
############ Begin Main
############
############

if ($opts{h}) { usage();}
if (!$opts{p}) { usage(); }
if (!$opts{u}) { usage(); }
if (!$opts{i}) { usage(); }

if ($opts{s}) { $SSL = 1; }
if ($opts{n}) { $NUM = $opts{n}; }

$IPADDRESS = $opts{i};
$USERNAME = $opts{u};
$PASSWORD = $opts{p};

if ($opts{l})
{
  $ID1 = $opts{l} + 1;
}
else
{
  $ID1 = 0;
}

if ($opts{a} eq 'query')
{
  my $QUERY = $ARGV[0];
  if ($QUERY eq '') { usage(); }
  my $META = $opts{m};
  unless ($ID1 > 0)
  {
    ($ID1,$ID2) = summaryinfo($SSL);
  }
  query($ID1,$ID2,$SSL,$NUM,$QUERY,$META);
  if ($opts{o} eq 'tree')
  {
    printtreeresults();
  }
  elsif ($opts{o} eq 'summary')
  {
    printsummaryresults();
  }
  elsif ($opts{o} eq 'csv')
  {
    printcsv();
  }
    elsif ($opts{o} eq 'normalized')
  {
    printnormalized();
  }
}


if ($opts{a} eq 'extract')
{
  unless ($ID1 > 0)
  {
    ($ID1,$ID2) = summaryinfo($SSL);
  }
  print "Extracting Files\n";
  if ($opts{o})
  {
    extractfiles($ID1,$ID2,$SSL,$NUM,$ARGV[0],$opts{o});
  }
  else
  {
    extractfiles($ID1,$ID2,$SSL,$NUM,$ARGV[0],"./");
  }
}

if ($opts{a} eq 'lastmeta')
{ 
  my $lastid = getlastsession($SSL,0,0);
  
  print "Setting the last meta id to $lastid, the value is stored in .lastmeta, this is useful for running this script via cron\n";
  
  if ($opts{t})
  {
    open(OUT, ">.lastmeta");
    print OUT "$lastid";
    close(OUT);
  }
}
