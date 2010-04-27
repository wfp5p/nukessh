#! /usr/bin/perl

# Linux version uses iptable and parses OpenSSH logs

use strict;
use POSIX;

use File::Tail;
use GDBM_File;

use AppConfig;
use Log::Log4perl qw(get_logger);
use Log::Log4perl::Level;
use IPTables::ChainMgr;

my $DUMPTABLE = 0;
my $CHAIN     = 'nukessh';          # name of chain in iptables
my $config    = AppConfig->new();

our $nextExpireRun;
our $NOW;
our %DBM;
our %ipcount;

# options for IPTables::ChainMgr
my %ipt_opts = (
             'iptables' => '/sbin/iptables',
             'iptout'   => '/tmp/iptables.out',
             'ipterr'   => '/tmp/iptables.err',
             'debug'    => 0,
	    'verbose'  => 1);

sub validateNumber # only valid if number >0
{
    my ($varname, $value) = @_;

    return ($value > 0);
}

sub doconfigure
{
    $config->define('configfile',
                    {  ARGS    => '=s',
                       DEFAULT => ''
                    });

    # log4perl config file
    $config->define('log4perl',
                    {  ARGS    => '=s',
                       DEFAULT => ''
                    });

    $config->define('pidfile',
                    {  ARGS    => '=s',
                       DEFAULT => ''
                    });

    # were to put the jump rule
    $config->define('jumplocation',
                    {  ARGS    => '=i',
                       DEFAULT => '4',
		       VALIDATE => \&validateNumber
                    });

    # which log should we monitor
    $config->define('readlog',
                    {  ARGS    => '=s',
                       DEFAULT => '/var/log/secure'
                    });

    # name of our logfile
    $config->define('logfile',
                    {  ARGS    => '=s',
                       DEFAULT => '/var/log/nukessh/nukessh.log'
                    });

    # name of dbm file
    $config->define('dbmfile',
                    {  ARGS    => '=s',
                       DEFAULT => '/var/cache/nukessh/nukedbm'
                    });

    # how often do we run the expire process
    $config->define('cycle',
                    {  ARGS    => '=i',
                       DEFAULT => '3600',
		       VALIDATE => \&validateNumber
                    });

    # how many failures are removed for each host during the expire
    $config->define('decay',
                    {  ARGS    => '=i',
                       DEFAULT => '10',
		       VALIDATE => \&validateNumber
                    });

    # how long does a host stay blocked in seconds
    $config->define('blocktime',
                    {  ARGS    => '=i',
                       DEFAULT => '43200',
		       VALIDATE => \&validateNumber
                    });

    # how many failures before a host is blocked
    $config->define('threshold',
                    {  ARGS    => '=i',
                       DEFAULT => '100',
		       VALIDATE => \&validateNumber
                    });

    # fork in background
    $config->define('daemon',
                    {  ARGS    => '!',
                       DEFAULT => '1'
                    });

    $config->define('debug', { ARGS => '!' });

    $config->getopt();

    if ($config->configfile() ne "") {
        if (-r $config->configfile()) {
            $config->file($config->configfile());

            # read options again so that command line overrides
            $config->getopt();
        }
        else {
            my $cf = $config->configfile();
            die "can not read configfile $cf";
        }
    }
}

sub set_dump
{
    $DUMPTABLE = 1;
}

sub blockHost
{
    my $ip     = shift;
    my $force  = shift;
    my $logger = get_logger();
    my $ipt    = new IPTables::ChainMgr(%ipt_opts)
      or $logger->logdie("ChainMgr failed");

    # try not to add a host to the tables twice
    if ( (!$force) && (defined $DBM{$ip}) && ($DBM{$ip} > $NOW) ) {
	$logger->trace("possible attempt to block $ip twice");
	return;
    }

    $logger->warn("blocking $ip");
    $ipt->append_ip_rule($ip, '0.0.0.0/0', 'filter', $CHAIN, 'DROP');

    # add to DBM, remove from ipcount
    if ( (!defined $DBM{$ip}) || ($DBM{$ip} < $NOW) )  {
	$DBM{$ip} = $NOW + $config->blocktime();
    }

    delete $ipcount{$ip};

}

sub unblockHost
{
    my $ip     = shift;
    my $logger = get_logger();
    my $ipt    = new IPTables::ChainMgr(%ipt_opts)
      or $logger->logdie("ChainMgr failed");

    $ipt->delete_ip_rule($ip, '0.0.0.0/0', 'filter', $CHAIN, 'DROP');

    delete $DBM{$ip};

    $logger->warn("unblocking $ip");
}

sub dumpTable
{
    my $entry;
    my $logger = get_logger();

    $logger->warn("Dumping ipcounts table:");

    while (my ($key, $val) = each %ipcount) {
        $logger->warn("  $key $val");
    }

    $logger->warn("Dumping DBM file:");

    while (my ($key, $val) = each %DBM) {
        $logger->warn("  $key $val");
    }

    $DUMPTABLE = 0;
}

sub expireHosts
{
    my $entry;
    my $logger = get_logger();

    $logger->debug("Doing expire.....");

    while (my ($ip, $count) = each %ipcount) {
        if ($count <= $config->decay()) { delete $ipcount{$ip}; }
        else { $ipcount{$ip} -= $config->decay(); }
    }

    while (my ($ip, $expire) = each %DBM) {
        if ($expire < $NOW) { unblockHost($ip); }
    }

    $nextExpireRun = $NOW + $config->cycle();

    $logger->debug("Expire done, next expire at $nextExpireRun");

}

sub dumpConfig
{

    my $logger = get_logger();

    if ($logger->is_debug()) {
        my %vars = $config->varlist(".*");

        $logger->debug("Configuration options:");

        while (my ($var, $value) = each %vars) {
            $logger->debug("$var : $value");
        }
    }
}

sub startlogging
{
    my ($filename, $debug) = @_;
    my $logfile = $config->logfile();

    if ($filename ne "") {
        Log::Log4perl->init($filename);

    }
    else {
        my $logconfig = "
log4perl.rootLogger=WARN, LOGFILE
log4perl.appender.LOGFILE=Log::Log4perl::Appender::File
log4perl.appender.LOGFILE.filename=$logfile
log4perl.appender.LOGFILE.mode=append

log4perl.appender.LOGFILE.layout=PatternLayout
log4perl.appender.LOGFILE.layout.ConversionPattern=\%d \%F - \%m\%n
";
        Log::Log4perl->init(\$logconfig);
    }

    if ($debug) {
        my $logger = get_logger();
        $logger->level($DEBUG);
    }
}

sub createChain
{
    my $logger = get_logger();
    my $ipt    = new IPTables::ChainMgr(%ipt_opts)
      or $logger->logdie("ChainMgr failed");

    my ($rv, $out_aref, $err_aref) = $ipt->chain_exists('filter', $CHAIN);

    $ipt->delete_chain('filter', 'INPUT', $CHAIN) if ($rv);

    $ipt->create_chain('filter', $CHAIN);
    $ipt->add_jump_rule('filter', 'INPUT', $config->jumplocation(), $CHAIN);

    # add blocked hosts back
    while (my ($ip, $expire) = each %DBM) {
        if ($expire > $NOW) { blockHost($ip,1); }
    }
}

### begins main body

doconfigure();
startlogging($config->log4perl(), $config->debug());
my $logger = get_logger();
dumpConfig();

if ($config->daemon()) {

    ## no critic
    open(STDIN,  "</dev/null");
    open(STDOUT, ">/dev/null");
    open(STDERR, ">/dev/null");
    ## use critic

    if (my $pid = fork()) {
        if ($config->get('pidfile') ne "") {
            open my $outfile, '>', $config->get('pidfile');
            print $outfile "$pid\n";
            close $outfile;
        }
        exit 0;
    }
    setsid;
}

## no critic

tie %DBM, "GDBM_File", $config->dbmfile(),, O_RDWR | O_CREAT, 0640
  or $logger->logdie("Unable to open DBM database");

$NOW = time();

## use critic

createChain();

$nextExpireRun = time + $config->cycle();

$SIG{USR2} = \&set_dump;

my $file = File::Tail->new(name => $config->readlog());

$logger->warn("nukessh started");

my $line;

while (defined($line = $file->read)) {
    $NOW = time();

    $logger->trace("examining line: $line");

    if ($line =~
        /sshd\[\d+\]: Failed password for .* from (\d+\.\d+\.\d+\.\d+) port/)
    {
        my $ip = $1;

        $ipcount{$ip}++;

        blockHost($ip) if ($ipcount{$ip} > $config->threshold());

    }

    expireHosts() if ($NOW > $nextExpireRun);
    dumpTable if ($DUMPTABLE);
}
