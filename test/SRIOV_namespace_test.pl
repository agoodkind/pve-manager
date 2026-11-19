#!/usr/bin/perl

use strict;
use warnings;

use IPC::Open2;
use Test::More;
use PVE::SRIOV;

$ENV{PATH} = '/usr/sbin:/usr/bin:/sbin:/bin';
for my $shared (1, 0) {
    my @command = $shared ? ('/bin/cat') : ('/usr/bin/unshare', '--net', '--', '/bin/cat');
    my $pid = open2(my $output, my $input, @command);
    print {$input} "ready\n";
    my $ready = <$output>;
    die "The network namespace test process did not start.\n" if !defined($ready);
    my $identity = readlink("/proc/$pid/ns/net") // die "Cannot read the test namespace for PID $pid: $!\n";
    my $namespace = PVE::SRIOV::open_container_netns($pid);
    close($input);
    waitpid($pid, 0);
    die "The network namespace test process exited with status $?.\n" if $?;
    if ($shared) {
        ok(!defined($namespace), 'The scanner skips a second process sharing the host network namespace');
    } else {
        ok(defined($namespace), 'The scanner opens a separate Linux network namespace');
        my $actual = PVE::SRIOV::output([PVE::SRIOV::enter_netns($namespace), '/usr/bin/readlink', '/proc/self/ns/net']);
        chomp $actual;
        is($actual, $identity, 'nsenter uses the verified namespace even after the original process exits');
    }
    eval { PVE::SRIOV::open_container_netns($pid) };
    like("$@", qr{Cannot open the network namespace at \Q/proc/$pid/ns/net\E:}, 'An unavailable namespace reports its path');
}
done_testing();
