#! /usr/bin/perl

# Linux version uses iptable and parses OpenSSH logs

use strict;
use POSIX;

use File::Tail;
use Socket;
use GDBM_File;
use Getopt::Long;

use Log::Dispatch;
use Log::Dispatch::File;



our ($DEBUG, $DEBUGOPT, $LOG, $NOW);
our %DBM;
our %ipcount;

my $DUMPTABLE = 0;
my $READLOG='/var/log/secure'; # This may be /var/log/messages for some systems
my $LOGFILE='/var/log/nukessh/nukessh.log';
my $NUKEDBM='/var/cache/nukessh/nukedbm';
my $EXPIRECYCLE = 3600;
my $EXPIRE=43200; # how long a host stays blocked
my $DECAY=10;
my $THRESHOLD=100;
my $PIDFILE;


GetOptions('debug',\$DEBUGOPT,
	   'pidfile=s', \$PIDFILE);

$DEBUG=1 if ($DEBUGOPT);

# run in background
## no critic



open(STDIN,"</dev/null");
open(STDOUT,">/dev/null");
open(STDERR,">/dev/null");

## use critic

if (my $pid = fork())
{
    if ($PIDFILE)
    {
	open my $outfile, '>', $PIDFILE;
	print $outfile "$pid\n";
	close $outfile;
    }
    exit 0;
}

setsid;

# set up logging

sub addTS # add a timestamp to the log entry
{
    my %p = @_;

    return strftime("%b %e %H:%M:%S %Y ",localtime) . $p{message} . "\n";
}


$LOG = Log::Dispatch->new;
$LOG->add(Log::Dispatch::File->new(name => 'logfile',
				   min_level => 'debug',
				   filename => $LOGFILE,
				   callbacks => \&addTS));


## no critic

tie %DBM, "GDBM_File", $NUKEDBM, O_RDWR|O_CREAT, 0640
   or die "Unable to open DBM database";

## use critic


my $nextExpireRun = time + $EXPIRECYCLE;

$SIG{USR1}=\&flip_debug;
$SIG{USR2}=\&set_dump;

sub set_dump
{
  $DUMPTABLE = 1;
}

sub flip_debug
{
   $DEBUG = (! $DEBUG );
}

sub logIt
{
  my ($message,$force) = @_;

  return if ( (! $DEBUG) && ( ! $force) );

  $LOG->log(level=>'debug', message => $message);

}

sub blockHost
{
    my $ip = shift;

    system "/sbin/iptables -A nukessh -s $ip -j DROP";

    $DBM{$ip} = $NOW + $EXPIRE;

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

   my $saveDebug = $DEBUG;
   my $entry;

   $DEBUG = 1;

   logIt ("Dumping ipcounts table:");

    while (my ($key,$val) = each %ipcount)
    {
	logIt ("  $key $val");
    }

   logIt ("Dumping DBM file:");

   while  ( my ($key,$val) = each %DBM)
   {
      logIt ("  $key $val");
   }

   $DUMPTABLE = 0;
   $DEBUG = $saveDebug;
}



sub expireHosts
{
   my $entry;

   logIt("Doing expire.....");

   while  ( my ($key,$val) = each %ipcount)
   {
       if ($val <= $DECAY) { delete $ipcount{$key}; }
       else { $ipcount{$key} -= $DECAY; }
   }

   while  ( my ($key,$val) = each %DBM)
   {
       if ($DBM{$key} < $NOW)
       {
           unblockHost($key);

       }

   }

   $nextExpireRun = $NOW + $EXPIRECYCLE;

   logIt("Expire done, next expire at $nextExpireRun");

}

my $file = File::Tail->new(name=>$READLOG, maxinterval=>10);

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

       blockHost($ip) if ($ipcount{$ip} > $THRESHOLD );

   }

   expireHosts() if ($NOW > $nextExpireRun);

   dumpTable if ($DUMPTABLE);

}





