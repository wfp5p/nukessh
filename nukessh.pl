#! /usr/bin/perl

# Linux version uses iptable and parses OpenSSH logs

use strict;
use POSIX;

use File::Tail;
use Socket;
use GDBM_File;

use Log::Dispatch;
use Log::Dispatch::File;

use AppConfig;


our ($LOG, $NOW);
our %DBM;
our %ipcount;

my $DUMPTABLE = 0; # flag is true if tables should be dumped to log

my $config = AppConfig->new();

$config->define('configfile', {ARGS => '=s',
			       DEFAULT => '' });

$config->define('pidfile', {ARGS => '=s',
			    DEFAULT => '' });

# which log should we monitor
$config->define('readlog', {ARGS => '=s',
			    DEFAULT => '/var/log/secure' });

# name of our logfile
$config->define('logfile', {ARGS => '=s',
			    DEFAULT => '/var/log/nukessh/nukessh.log' });

# name of dbm file
$config->define('dbmfile', {ARGS => '=s',
			    DEFAULT => '/var/cache/nukessh/nukedbm' });

# how often do we run the expire process
$config->define('cycle', {ARGS => '=i',
			    DEFAULT => '3600' });

# how many failures are removed for each host during the expire
$config->define('decay', {ARGS => '=i',
			    DEFAULT => '10' });


# how long does a host stay blocked in seconds
$config->define('blocktime', {ARGS => '=i',
			    DEFAULT => '43200' });

# how many failures before a host is blocked
$config->define('threshold', {ARGS => '=i',
			    DEFAULT => '100' });

# fork in background
$config->define('daemon', {ARGS => '!',
			    DEFAULT => '1' });

$config->define('debug', {ARGS => '!'});

$config->getopt();

if ($config->configfile() ne "")
{
    if (-r $config->configfile())
    {
	$config->file($config->configfile());
	# read options again so that command line overrides
	$config->getopt();
    }
    else
    {
	my $cf = $config->configfile();
	die "can not read configfile $cf";
    }
}


if ($config->daemon())
{

    ## no critic
    open(STDIN,"</dev/null");
    open(STDOUT,">/dev/null");
    open(STDERR,">/dev/null");
    ## use critic

    if (my $pid = fork())
    {
	if ($config->get('pidfile') ne "")
	{
	    open my $outfile, '>', $config->get('pidfile');
	    print $outfile "$pid\n";
	    close $outfile;
	}
	exit 0;
    }

    setsid;
}

# set up logging

sub addTS # add a timestamp to the log entry
{
    my %p = @_;

    return strftime("%b %e %H:%M:%S %Y ",localtime) . $p{message} . "\n";
}


$LOG = Log::Dispatch->new;
$LOG->add(Log::Dispatch::File->new(name => 'logfile',
				   min_level => 'debug',
				   filename => $config->logfile(),
				   callbacks => \&addTS));


## no critic

tie %DBM, "GDBM_File", $config->dbmfile(),, O_RDWR|O_CREAT, 0640
   or die "Unable to open DBM database";

## use critic


my $nextExpireRun = time + $config->cycle();

$SIG{USR1}=\&flip_debug;
$SIG{USR2}=\&set_dump;

sub set_dump
{
  $DUMPTABLE = 1;
}

sub flip_debug
{
    my $x = $config->get('debug');
    $config->set('debug', (!$x));
}

sub logIt
{
  my ($message,$force) = @_;

  return if ( (! $config->debug()) && ( ! $force) );

  $LOG->log(level=>'debug', message => $message);

}

sub blockHost
{
    my $ip = shift;

    system "/sbin/iptables -A nukessh -s $ip -j DROP";

    $DBM{$ip} = $NOW + $config->blocktime();

    delete $ipcount{$ip};

    logIt("blocking $ip",1);

}

sub unblockHost
{
    my $ip = shift;

    system "/sbin/iptables -D nukessh -s $ip -j DROP";

    delete $DBM{$ip};

    logIt("unblocking $ip",1);

}

sub dumpTable
{

   my $entry;

   logIt ("Dumping ipcounts table:",1);

    while (my ($key,$val) = each %ipcount)
    {
	logIt ("  $key $val",1);
    }

   logIt ("Dumping DBM file:",1);

   while  ( my ($key,$val) = each %DBM)
   {
      logIt ("  $key $val",1);
   }

   $DUMPTABLE = 0;
}



sub expireHosts
{
   my $entry;

   logIt("Doing expire.....");

   while  ( my ($key,$val) = each %ipcount)
   {
       if ($val <= $config->decay()) { delete $ipcount{$key}; }
       else { $ipcount{$key} -= $config->decay(); }
   }

   while  ( my ($key,$val) = each %DBM)
   {
       if ($DBM{$key} < $NOW)
       {
           unblockHost($key);

       }

   }

   $nextExpireRun = $NOW + $config->cycle();

   logIt("Expire done, next expire at $nextExpireRun");

}

my $file = File::Tail->new(name=>$config->readlog(), maxinterval=>10);

logIt ("nukessh started",1);

my $line;

while (defined ($line=$file->read))
{
   $NOW = time();
   $_ = $line;

   if (/sshd\[\d+\]: Failed password for .* from (\d+\.\d+\.\d+\.\d+) port/)
   {
       my $ip = $1;

       $ipcount{$ip}++;

       blockHost($ip) if ($ipcount{$ip} > $config->threshold() );

   }

   expireHosts() if ($NOW > $nextExpireRun);

   dumpTable if ($DUMPTABLE);

}





