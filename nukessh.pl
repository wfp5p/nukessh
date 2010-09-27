#! /usr/bin/perl

# Linux version uses iptable and parses OpenSSH logs

use strict;
use POSIX;

use POE qw(Wheel::FollowTail);
use AppConfig;
use Log::Log4perl qw(get_logger);
use Log::Log4perl::Level;
use IPTables::ChainMgr;
use File::Temp qw(mktemp);
use List::Util qw(first);
use App::Daemon qw(detach);
use NukeDB;

my $CHAIN     = 'nukessh';          # name of chain in iptables
my $config    = AppConfig->new();

our $nukedb;
our %ipcount;

# options for IPTables::ChainMgr
my %ipt_opts = (
             'iptables' => '/sbin/iptables',
	     'iptout'   => mktemp('/tmp/nukessh.XXXXXX'),
             'ipterr'   => mktemp('/tmp/nukessh.XXXXXX'),
             'debug'    => 0,
	     'verbose'  => 0);

# for hardcore mode, any attempt to log into these gets and immediate nuke
my @badusers = qw(nobody apache tomcat postgres zabbix squid postfix
		  munin mysql news gopher mail);

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
                       DEFAULT => '/var/cache/nukessh/nukedb'
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
    $config->define('hardcore', { ARGS => '!' });

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
    my $logger = get_logger();
    $logger->debug("set_dump");

    $poe_kernel->post( "expirer", "sig_usr2", 0);
    $poe_kernel->sig_handled();
}

sub blockHost
{
    my $ip     = shift;
    my $force  = shift;
    my $logger = get_logger();
    my $NOW = time();
    my $ipt    = new IPTables::ChainMgr(%ipt_opts)
      or $logger->logdie("ChainMgr failed");

    # try not to add a host to the tables twice 7!
    # if ( (!$force) && (defined $DBM{$ip}) && ($DBM{$ip}->{expire} > $NOW) ) {
    # 	$logger->trace("possible attempt to block $ip twice");
    # 	return;
    # }

    $logger->warn("blocking $ip");
    $ipt->append_ip_rule($ip, '0.0.0.0/0', 'filter', $CHAIN, 'DROP');

    # add to DB, remove from ipcount
    $nukedb->insertexpire($ip, $NOW + $config->blocktime()) if (!$force);

    delete $ipcount{$ip};
    return;
}

sub unblockHost
{
    my $ip     = shift;
    my $logger = get_logger();
    my $ipt    = new IPTables::ChainMgr(%ipt_opts)
      or $logger->logdie("ChainMgr failed");

    $ipt->delete_ip_rule($ip, '0.0.0.0/0', 'filter', $CHAIN, 'DROP');

    $nukedb->clearexpire($ip);

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

    # $logger->warn("Dumping DBM file:");

    # while (my ($key, $val) = each %DBM) {
    # 	my $expire = $val->{expire};
    # 	my $blocks = $val->{blocks};

    # 	$logger->warn(" $key expire: $expire blocks: $blocks");
    # }

}

sub expireHosts
{
    my $entry;
    my $NOW = time();
    my $logger = get_logger();

    $logger->debug("Doing expire.....");

    while (my ($ip, $count) = each %ipcount) {
        if ($count <= $config->decay()) { delete $ipcount{$ip}; }
        else { $ipcount{$ip} -= $config->decay(); }
    }

    foreach my $ip ($nukedb->getexpires($NOW)) {
	unblockHost($ip);
    }
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
log4perl.appender.LOGFILE.recreate = 1
log4perl.appender.LOGFILE.recreate_check_signal = HUP
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
    my $NOW = time();
    my $ipt    = new IPTables::ChainMgr(%ipt_opts)
      or $logger->logdie("ChainMgr failed");

    my ($rv, $out_aref, $err_aref) = $ipt->chain_exists('filter', $CHAIN);

    $ipt->delete_chain('filter', 'INPUT', $CHAIN) if ($rv);

    $ipt->create_chain('filter', $CHAIN);
    $ipt->add_jump_rule('filter', 'INPUT', $config->jumplocation(), $CHAIN);

    # add blocked hosts back
    foreach my $ip ($nukedb->getactive($NOW)) {
	blockHost($ip,1);
    }
}

### begins main body

doconfigure();

if ($config->daemon()) {

    if ($config->get('pidfile') ne "") {
	$App::Daemon::pidfile = $config->get('pidfile');
    }
    else {
	$App::Daemon::pidfile = "/tmp/nukessh.pid";
    }
    detach();
}

startlogging($config->log4perl(), $config->debug());
my $logger = get_logger();
dumpConfig();

$nukedb = NukeDB->new(DB => $config->dbmfile()) or $logger->logdie("Unable to open database");



if ($config->hardcore) {
    $logger->warn("nukessh started in hardcore mode");
}
else
{
   $logger->warn("nukessh started");
}

POE::Session->create(
   inline_states => {
       _start => sub {
	   $_[KERNEL]->alias_set("expirer");
	   $_[KERNEL]->delay(expire => $config->cycle);
	   $_[KERNEL]->yield('create_chain');
	   },
       create_chain => \&createChain,
       sig_usr2 => \&dumpTable,
       expire => sub {
	   expireHosts();
	   $_[KERNEL]->delay(expire => $config->cycle);
       }});

POE::Session->create(
   inline_states => {
       _start => sub {
	   $_[HEAP]{fn} = POE::Wheel::FollowTail->new(
               Filename =>  $config->readlog(),
  	       InputEvent => "log_line");
       },
       log_line => \&process_line,
		    });

$SIG{USR2} = \&set_dump;
$SIG{TERM} = \&cleanup;
POE::Kernel->run();

sub cleanup
{
    $poe_kernel->stop();
    unlink $ipt_opts{iptout};
    unlink $ipt_opts{ipterr};
}

sub process_line
{
    my $line = $_[ARG0];

    $logger->trace("examining line: $line");

    if ($line =~
        /sshd\[\d+\]: Failed password for (?:invalid user )?(.*) from (\d+\.\d+\.\d+\.\d+) port/)
    {
        my ($user,$ip) = ($1,$2);

        $ipcount{$ip}++;

	if ( ($config->hardcore()) && (first {$user eq $_} @badusers) ) {
	    $logger->warn("$ip wins the bonus round with $user!");
	    $ipcount{$ip} += $config->threshold() + 1;
	}

        blockHost($ip) if ($ipcount{$ip} > $config->threshold());
    }
}
