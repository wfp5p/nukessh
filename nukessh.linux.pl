#! /uva/bin/perl

# Linux version uses iptable and parses OpenSSH logs

use POSIX;
use File::Tail;
use Socket;
use GDBM_File;
use Getopt::Long;
use FileHandle;


$READLOG='/var/log/messages';
$LOGFILE='/etc/uva/nukessh/nukessh.log';
$NUKEDBM='/etc/uva/nukessh/nukedbm';
$EXPIRECYCLE = 3600;
$EXPIRE=43200; # how long a host stays blocked
$DECAY=10;
$THRESHOLD=100;

GetOptions('debug',\$DEBUGOPT);

$DEBUG=1 if ($DEBUGOPT);

# run in background
open(STDIN,"</dev/null");
open(STDOUT,">/dev/null");
open(STDERR,">/dev/null");

exit 0 if (fork());
setsid;

$LOG = new FileHandle ">> $LOGFILE";
$LOG->autoflush(1);

tie %DBM, "GDBM_File", $NUKEDBM, O_RDWR|O_CREAT, 0640
   or die "Unable to open DBM database";



$nextExpireRun = time + $EXPIRECYCLE;

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

  my $now_string = strftime "%b %e %H:%M:%S %Y", localtime();

  print $LOG "$now_string $message\n";
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

   undef $DUMPTABLE;
   $DEBUG = saveDebug;
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

$file = File::Tail->new(name=>$READLOG, maxinterval=>10);

logIt ("nukessh started",1);

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





