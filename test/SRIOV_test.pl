#!/usr/bin/perl

use strict;
use warnings;

use Fcntl qw(:flock);
use IO::Select;
use POSIX qw(_exit);
use Test::More;
use PVE::API2::SRIOV;

sub request {
    my ($method, $ifname, $body) = @_;
    my $param = { node => 'localhost', %{ $body // {} } };
    my ($handler, $info) = PVE::API2::SRIOV->find_handler($method, $ifname, $param);
    die "$method $ifname did not resolve to a Proxmox API handler.\n" if !$handler;
    return $handler->handle($info, $param, 1);
}

for my $method (qw(GET PUT)) {
    my (undef, $info) = PVE::API2::SRIOV->find_handler($method, 'lo', { node => 'localhost' });
    my $field = $info->{returns}->{properties}->{vfs}->{items}->{properties}->{in_container};
    is($field->{type}, 'boolean', "$method exposes a Boolean container location for each runtime VF");
    ok(!$field->{optional}, "$method requires the container location in the response");
}

for my $method (qw(GET PUT DELETE)) {
    my $body = $method eq 'PUT' ? { numvfs => 1, vfs => [] } : {};
    eval { request($method, 'lo', $body) };
    like("$@", qr/does not support SR-IOV/, "$method rejects the loopback interface");
    eval { request($method, 'absent-sriov-pf', $body) };
    like("$@", qr/does not exist/, "$method rejects a missing adapter");
}

eval { request('PUT', 'lo', { numvfs => 1, vfs => [{ index => 0, mac => '02:00:00:00:00:01' }] }) };
like("$@", qr/driver/, 'PUT requires a driver for each declared VF');
eval { request('PUT', 'lo', { numvfs => 1, vfs => [{ index => 0, mac => 'invalid', driver => 'iavf' }] }) };
like("$@", qr/mac/, 'PUT rejects an invalid VF MAC address');
eval { request('PUT', 'lo', { numvfs => 1, vfs => [{ index => 0, mac => '02:00:00:00:00:01', driver => 'iavf', vmid => 100 }] }) };
like("$@", qr/vmid/, 'PUT rejects a guest attachment field');
eval { request('PUT', 'lo', {
    numvfs => 1, vfs => [{ index => 0, mac => '02:00:00:00:00:01', driver => 'iavf', in_container => 1 }],
}) };
like("$@", qr/in_container/, 'PUT rejects the computed container location in a declaration');
for my $case (
    ['QEMU', \&PVE::QemuServer::PCI::lock_hostpci_for_start, { hostpci0 => 'mapping=test-vf' }],
    ['LXC', \&PVE::LXC::lock_hostnics_for_start, { hostnic0 => 'link=test-vf' }],
) {
    my ($label, $attach, $config) = @$case;
    open(my $writer_lock, '>>', PVE::SRIOVLock::PATH) or die "Cannot open the node lock: $!\n";
    flock($writer_lock, LOCK_EX) or die "Cannot acquire the node lock: $!\n";
    ok(!defined($attach->({})), "$label skips the node lock for a guest without physical devices");

    pipe(my $events, my $child_output) or die "Cannot create the attachment pipe: $!\n";
    pipe(my $release, my $continue) or die "Cannot create the release pipe: $!\n";
    my $pid = fork() // die "Cannot fork the attachment process: $!\n";
    if (!$pid) {
        close($writer_lock);
        close($events);
        close($continue);
        $child_output->autoflush(1);
        print {$child_output} "starting\n";
        my $reader = $attach->($config);
        print {$child_output} "attached\n";
        scalar(<$release>);
        _exit(defined($reader) ? 0 : 1);
    }
    close($child_output);
    close($release);
    is(scalar(<$events>), "starting\n", "$label starts a new guest during a mutation");
    my $ready = IO::Select->new($events);
    ok(!$ready->can_read(0.25), "$label waits for the exclusive mutation to finish");
    close($writer_lock);
    ok($ready->can_read(5), "$label resumes after mutation");
    is(scalar(<$events>), "attached\n", "$label acquired the shared attachment lock");
    open(my $probe, '>>', PVE::SRIOVLock::PATH) or die "Cannot open the lock probe: $!\n";
    ok(!flock($probe, LOCK_EX | LOCK_NB), "$label excludes a mutation during attach");
    ok(flock($probe, LOCK_SH | LOCK_NB), "$label allows another guest to attach concurrently");
    close($probe);
    close($continue);
    close($events);
    waitpid($pid, 0);
    is($?, 0, "$label releases the lock after attach");
}
my $missing_link = 'absent-sriov-pf';
eval { PVE::LXC::vm_start(299999999, { hostnic0 => "link=$missing_link" }) };
like("$@", qr/Host interface '\Q$missing_link\E' does not exist/, 'LXC startup fails at the physical interface check');
open(my $after_failure, '>>', PVE::SRIOVLock::PATH) or die "Cannot inspect the node lock: $!\n";
ok(flock($after_failure, LOCK_EX | LOCK_NB), 'LXC releases the shared lock after startup rejects the device');
close($after_failure);
done_testing();
