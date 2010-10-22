package NukeDB;

use strict;
use Carp;
use DBI;
use Data::Alias;

our $VERSION = '0.01';

sub new
{
    my ($class, %arg) = @_;
    my $this;

    croak "database not defined!" if ( !defined $arg{DB} );

    $this->{dbh} = DBI->connect("dbi:SQLite:dbname=$arg{DB}","","") or croak;

    my @tables = $this->{dbh}->selectrow_array("select name from sqlite_master where name='nukessh' and type='table'");
    if ($#tables == -1) {
	$this->{dbh}->do("create table nukessh (ip text primary key,
                                    expire integer default 0,
                                    blocks integer default 0,
                                    lastupdate TIMESTAMP)");
    }
    else {
	$this->{dbh}->do("vacuum");
    }

    $this->{dbh}->do("create trigger if not exists mktime_insert after insert on nukessh begin
                      update nukessh set lastupdate=strftime('%s','now') where
                      ip = new.ip;end;");
    $this->{dbh}->do("create trigger if not exists mktime_update after update on nukessh begin
                      update nukessh set lastupdate=strftime('%s','now') where
                      ip = new.ip;end;");

    bless $this, $class;
    return $this;
}


sub insertexpire
{
    my $this = shift;
    alias my $dbh = $this->{dbh};
    my $ip = $dbh->quote(shift @_);
    my $expire = shift;

    my @row = $dbh->selectrow_array("select ip,expire from nukessh where ip=$ip");
    if ($#row != -1) {
	if ($row[1] < $expire) {
	    $dbh->do("update nukessh set expire=$expire, blocks=blocks + 1 where ip=$ip");
	}
    } else {
	$dbh->do("insert into nukessh (ip, expire, blocks) VALUES ($ip, $expire,1)");
    }
}

# allow insertion of values explicitly
sub insert
{
    my $this = shift;
    alias my $dbh = $this->{dbh};
    my $ip = $dbh->quote(shift @_);
    my $expire = shift;
    my $blocks = shift;

    $dbh->do("insert or replace into nukessh (ip, expire, blocks) VALUES ($ip, $expire,$blocks)");
}

# purge records where expire = 0 and lastupdate <= param
sub purge
{
    my $this = shift;
    alias my $dbh = $this->{dbh};
    my $purgetime = shift;

    $dbh->do("delete from nukessh where expire=0 and lastupdate <= $purgetime");
    $dbh->do("vacuum");
}

sub clearexpire
{
    my $this = shift;
    alias my $dbh = $this->{dbh};
    my $ip = $dbh->quote(shift @_);

    $dbh->do("update nukessh set expire=0 where ip=$ip");
}

# return array of all ips with expire > 0 and <= now
sub getexpires
{
    my $this = shift;
    my $now = shift;
    alias my $dbh = $this->{dbh};

    my $x = $dbh->selectall_arrayref("select ip from nukessh where expire > 0 and expire <= $now");

    my @x = map { $_->[0] } @$x;

    return @x;
}

# given an ip, return it's record as
# [ expire blocks lastupdate ]
sub getinfo
{
    my $this = shift;
    alias my $dbh = $this->{dbh};
    my $ip = $dbh->quote(shift @_);

    my @x = $dbh->selectrow_array("select expire, blocks, lastupdate from nukessh where ip=$ip");

    return @x;
}

sub getactive
{
    my $this = shift;
    my $now = shift;
    alias my $dbh = $this->{dbh};

    my $x = $dbh->selectall_arrayref("select ip from nukessh where expire != 0 and expire > $now");

    my @x = map { $_->[0] } @$x;

    return @x;
}



1;
