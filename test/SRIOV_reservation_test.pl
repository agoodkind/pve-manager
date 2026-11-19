#!/usr/bin/perl

use strict;
use warnings;

use POSIX qw(WNOHANG _exit);
use Test::More;
use PVE::QemuServer::PCI;
use PVE::QemuServer::Helpers;

my ($address, $vmid, $other) = @ARGV;
die "Specify a PCI address and two unused VMIDs on an isolated test node.\n"
    if !defined($other) || $vmid !~ /\A\d+\z/ || $other !~ /\A\d+\z/ || $vmid == $other
    || $address !~ /\A[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\z/;
die "Missing PCI device $address.\n" if !-e "/sys/bus/pci/devices/$address";
for my $id ($vmid, $other) {
    my @configs = (glob("/etc/pve/nodes/*/qemu-server/$id.conf"), glob("/etc/pve/nodes/*/lxc/$id.conf"));
    die "VMID $id is already in use.\n" if @configs || -e PVE::QemuServer::Helpers::vm_pidfile_name($id);
}
my $owners = sub { PVE::QemuServer::PCI::get_reservation_owners()->{$address} };
die "PCI device $address is reserved.\n" if defined($owners->());
my $child;
eval {
    PVE::QemuServer::PCI::reserve_pci_usage($address, $vmid, 0);
    is($owners->(), $vmid, 'A pending reservation protects the device before PID publication');
    eval { PVE::QemuServer::PCI::reserve_pci_usage($address, $other, 0) };
    like("$@", qr/currently reserved/, 'QEMU rejects another VM during the pending reservation');
    for (1 .. 70) {
        last if !defined($owners->());
        select(undef, undef, undef, 0.1);
    }
    is($owners->(), undef, 'An expired deadline releases ownership without manual cleanup');
    PVE::QemuServer::PCI::reserve_pci_usage($address, $other, 0);
    is($owners->(), $other, 'Another VM can reuse the expired reservation');

    my $pidfile = PVE::QemuServer::Helpers::vm_pidfile_name($other);
    $child = fork() // die "Cannot start QEMU: $!\n";
    if (!$child) {
        exec('/usr/bin/kvm', '-machine', 'none,accel=tcg', '-nodefaults', '-display', 'none',
            '-S', '-pidfile', $pidfile) or _exit(127);
    }
    my $running_pid;
    for (1 .. 100) {
        $running_pid = PVE::QemuServer::Helpers::vm_running_locally($other);
        last if defined($running_pid);
        if (waitpid($child, WNOHANG) == $child) {
            undef $child;
            die "The test QEMU process exited during startup: $?.\n";
        }
        select(undef, undef, undef, 0.1);
    }
    die "Proxmox could not identify the test QEMU process.\n" if !defined($running_pid);
    PVE::QemuServer::PCI::reserve_pci_usage($address, $other, undef, $running_pid);
    is($owners->(), $other, 'A running VM owns its PID reservation');
    eval { PVE::QemuServer::PCI::reserve_pci_usage($address, $vmid, 0) };
    like("$@", qr/already in use/, 'QEMU rejects another VM while the owner is running');
    kill('TERM', $child) or die "Cannot stop the test QEMU process: $!\n";
    waitpid($child, 0);
    undef $child;
    is($owners->(), undef, 'The exited VM releases ownership without manual cleanup');
    PVE::QemuServer::PCI::reserve_pci_usage($address, $vmid, 0);
    is($owners->(), $vmid, 'Another VM can reuse the exited owner reservation');
};
my $error = $@;
if ($child) {
    kill('TERM', $child);
    waitpid($child, 0);
}
PVE::QemuServer::PCI::remove_pci_reservation($_, [$address]) for ($vmid, $other);
die $error if $error;
done_testing();
