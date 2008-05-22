#! /uva/bin/perl

use lib '/common/uva/lib/toobp/lib/site_perl';
use lib '/common/uva/lib/toobp/lib/site_perl/aix';
use POSIX;
use File::Tail;
use Socket;
use NDBM_File;
use Getopt::Long;
use FileHandle;


$READLOG='/usr/local/squid/logs/access.log';
$LOGFILE='/etc/uva/nukessh/nukesquid.log';
$NUKEDBM='/etc/uva/nukessh/nukesquiddbm';
$EXPIRECYCLE = 3600;
$EXPIRE=43200; # how long a host stays blocked
$DECAY=10;
$THRESHOLD=100; # 

GetOptions('debug',\$DEBUGOPT);

$DEBUG=1 if ($DEBUGOPT);

# run in background


if ($pid = fork())
{
    print "$pid\n";
    exit 0;
}

setsid;

open(STDIN,"</dev/null");
open(STDOUT,">/dev/null");
open(STDERR,">/dev/null");

$LOG = new FileHandle ">> $LOGFILE";
$LOG->autoflush(1);

tie %DBM, "NDBM_File", $NUKEDBM, O_RDWR|O_CREAT, 0640
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
    
    system "/usr/sbin/route add $ip 0.0.0.0 -blackhole";
    
    $DBM{$ip} = $NOW + $EXPIRE;
    
    delete $ipcount{$ip};
    
    logIt("   blocking $ip",1);
    
}  

sub unblockHost
{   
    my $ip = shift;
    
    system "/usr/sbin/route delete $ip 0.0.0.0";
    
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

logIt ("nukesquid started",1);

while (defined ($line=$file->read))
{
   $NOW = time();
   $_ = $line;
   
   if (/(\S+)\s+TCP_DENIED\/407/)
   {
       my $ip = $1;

       if ( ! ($ip =~ /^128\.143\./) )
       {
	    $ipcount{$ip}++;
    
            blockHost($ip) if ($ipcount{$ip} > $THRESHOLD );
       }	   
   
   }      
   
   expireHosts() if ($NOW > $nextExpireRun);
   
   dumpTable if ($DUMPTABLE);
    
}   





