#!/usr/bin/perl -T

use strict;
use warnings;

use lib qw(.. .);

use HostArtifactsTest;
use HostArtifactsInstalledSourceTest;

die "this test does not accept arguments\n" if @ARGV;
my ($rpcenv, $fixture_dir, $user) = HostArtifactsTest::initialize_attested_fixture();
HostArtifactsInstalledSourceTest::run($rpcenv, $user, "$fixture_dir/installed-source");
exit(0);
