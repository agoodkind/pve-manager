#!/usr/bin/perl

use strict;
use warnings;

use POSIX qw(_exit);
use Time::HiRes qw(sleep time);
use Test::More;
use PVE::File;
use PVE::SRIOV;
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::RPCEnvironment;
use PVE::Storage;

my $id = shift // die "Specify an unused VMID on a disposable Proxmox node.\n";
my $rpc = PVE::RPCEnvironment->init('cli');
$rpc->set_user('root@pam');
if (@ARGV && $ARGV[0] eq '--start') {
    PVE::QemuServer::vm_start(PVE::Storage::config(), $id, {}, {});
    exit(0);
}
my $pci = 'ffff:ff:1f.7';
die "The test PCI address exists on this node.\n" if -e "/sys/bus/pci/devices/$pci";
my ($created, $child, $output);

eval {
    PVE::SRIOV::with_mutation_locks(sub {
        my ($inventory) = @_;
        die "The test VMID $id already exists.\n" if $inventory->{$id};
        PVE::QemuConfig->create_and_lock_config($id);
        $created = 1;
        PVE::QemuConfig->lock_config($id, sub {
            PVE::QemuConfig->write_config($id, {
                name => 'sriov-lock-test', memory => 128, kvm => 0, hostpci0 => $pci,
            });
        });
        pipe($output, my $writer) or die "Cannot create the startup result pipe: $!\n";
        $child = fork() // die "Cannot fork qm start: $!\n";
        if (!$child) {
            close($output);
            open(STDOUT, '>&', $writer) or _exit(126);
            open(STDERR, '>&', $writer) or _exit(126);
            exec($^X, $0, $id, '--start') or _exit(127);
        }
        close($writer);
        my $inode = (stat(PVE::SRIOVLock::PATH))[1] // die "Cannot inspect the node lock: $!\n";
        my $until = time() + 30;
        while (time() < $until) {
            my $locks = PVE::File::file_get_contents('/proc/locks');
            if ($locks =~ /^\d+: -> FLOCK\s+ADVISORY\s+READ\s+(\d+)\s+\S+:$inode\s/m) {
                my $command = PVE::File::file_get_contents("/proc/$1/cmdline");
                if (index($command, "$id") >= 0) {
                    pass('The new VMID waits for the active SR-IOV mutation at startup');
                    return;
                }
            }
            sleep(0.05);
        }
        die "VM startup did not wait on the exclusive attachment lock.\n";
    });
};
my $error = $@;
if ($child) {
    my $message = do { local $/; <$output> };
    close($output);
    waitpid($child, 0);
    isnt($?, 0, 'Startup rejects the nonexistent PCI device after the mutation finishes');
    like($message, qr/no PCI device found for '\Q$pci\E'/, 'QEMU resolves the PCI ID after acquiring the shared lock');
    diag($message) if $error;
}
PVE::QemuConfig->lock_config($id, sub { PVE::QemuConfig->destroy_config($id) }) if $created;
die $error if $error;
done_testing();
