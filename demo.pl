#! /usr/bin/perl

# Linux version uses iptable and parses OpenSSH logs

use strict;
use feature qw(say);
use lib "./pm";

use NukeDB;

my $nukedb = NukeDB->new(DB => "/tmp/nukedb") or die;

my ($expire, $blocks, $lastupdate);

($expire, $blocks, $lastupdate) = $nukedb->getinfo("125.46.63.134");

say "$expire $blocks";

($expire, $blocks, $lastupdate) = $nukedb->getinfo("60.13.122.139");

say "blah" if (!defined $expire);

say "$expire $blocks";

($expire, $blocks, $lastupdate) = $nukedb->getinfo("216.17.110.234");

say "$expire $blocks";
