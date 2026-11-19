#!/usr/bin/perl

use strict;
use warnings;

use JSON qw(decode_json);
use POSIX qw(_exit);
use Test::More;
use PVE::API2::SRIOV;
use PVE::File;
use PVE::Tools qw(run_command);

my $mode = shift // die "Specify unused, attached, or mapped.\n";
my $port = shift // die "Specify the dedicated physical interface.\n";
my $path = shift // die "Specify the JSON declaration file.\n";
my $desired = decode_json(PVE::File::file_get_contents($path));
my $json = JSON->new->canonical->allow_nonref;
my $node = PVE::INotify::nodename();

sub request {
    my ($method, $body) = @_;
    my $param = { node => $node, %{ $body // {} } };
    my ($handler, $info) = PVE::API2::SRIOV->find_handler($method, $port, $param);
    die "Cannot resolve $method for $port.\n" if !$handler;
    return $handler->handle($info, $param, 1);
}

sub check_declared_vfs {
    my ($state) = @_;
    is($state->{numvfs}, $desired->{numvfs}, 'The PF reports the requested number of VFs');
    for my $vf ($desired->{vfs}->@*) {
        my $actual = $state->{vfs}->[$vf->{index}];
        is($actual->{driver}, $vf->{driver}, "VF $vf->{index} binds to the declared driver");
        is($actual->{mac}, lc($vf->{mac}), "VF $vf->{index} uses the declared MAC");
        like($actual->{pci}, qr/\A[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\z/, 'GET reports the PCI address');
        is($actual->{ifname}, $vf->{ifname}, 'The network driver uses the stable name') if defined($vf->{ifname});
    }
}

my $before = request('GET');
if ($mode eq 'unused') {
    die "This test requires a dedicated unmanaged adapter with zero enabled VFs.\n"
        if $before->{numvfs} || exists($before->{desired});
    die "Declare at least one VF and a positive VF count.\n" if !@{ $desired->{vfs} } || !$desired->{numvfs};
    my $reserve_id = shift // die "Specify an unused VMID for the pending PCI reservation test.\n";
    die "The reservation test requires an unused VMID.\n"
        if $reserve_id !~ /\A\d+\z/ || PVE::Cluster::get_vmlist()->{ids}->{$reserve_id};
    my $isolated_node = shift // die "Specify the name of the isolated, guest-free test node.\n";
    die "The isolated test node '$isolated_node' does not match '$node'.\n" if $isolated_node ne $node;
    my $check_isolation = sub {
        my ($guests) = @_;
        die "This restore test requires a node without guests.\n" if keys %$guests;
        my $dir = '/etc/pve-overlay/sriov';
        if (-d $dir) {
            die "Direct restore would apply a declaration for another adapter.\n"
                if grep { /\.json\z/ && $_ ne "$port.json" } PVE::SRIOV::entries($dir);
        }
    };
    PVE::SRIOV::with_mutation_locks($check_isolation);
    my $after = request('PUT', $desired);
    is_deeply(request('GET'), $after, 'GET reads the enabled VFs and the saved declaration');
    check_declared_vfs($after);
    for my $vf ($after->{vfs}->@*) {
        is($json->encode($vf->{in_container}), 'false', "VF $vf->{index} reports false on the guest-free node");
    }
    is_deeply(request('PUT', $desired), $after, 'Repeated PUT preserves runtime and desired state');
    my $pci = $after->{vfs}->[$desired->{vfs}->[0]->{index}]->{pci};
    PVE::QemuServer::PCI::reserve_pci_usage($pci, $reserve_id, 30);
    eval { request('DELETE') };
    my $reserve_error = "$@";
    PVE::QemuServer::PCI::remove_pci_reservation($reserve_id, [$pci]);
    like($reserve_error, qr/in use by VM \Q$reserve_id\E\b/, 'A PCI reservation protects the VF before QEMU publishes its PID');
    PVE::SRIOV::with_mutation_locks(sub {
        my ($guests) = @_;
        $check_isolation->($guests);
        my $saved = PVE::SRIOV::saved($port);
        my ($state, $owners, $netns) = PVE::SRIOV::observe($port, $saved, $guests);
        die "Runtime or desired state changed before the restoration test.\n"
            if $json->encode($state) ne $json->encode($after);
        PVE::SRIOV::apply_port($port, $state, $owners, { numvfs => 0, vfs => [] }, $guests, $netns);
    });
    my $cleared = request('GET');
    is_deeply($cleared, { %$after, numvfs => 0, vfs => [] },
        'The kernel removed all VFs and the original declaration remains on disk')
        or BAIL_OUT('Cannot verify reconstruction without cleared runtime state');
    run_command(['/usr/bin/perl', '-T', '/usr/share/pve-overlay/sriov-restore']);
    my $restored = request('GET');
    is_deeply($restored->{desired}, $after->{desired}, 'The restore program preserves the saved declaration');
    check_declared_vfs($restored);
    for my $vf ($desired->{vfs}->@*) {
        my $index = $vf->{index};
        is($restored->{vfs}->[$index]->{pci}, $after->{vfs}->[$index]->{pci}, "Restore recreates VF $index at its PCI address");
    }
    request('DELETE');
    is_deeply(request('GET'), $before, 'DELETE restores the unused adapter');
} elsif ($mode eq 'attached') {
    my $index = shift // die "Specify the VF index in use by a running guest.\n";
    my $vmid = shift // die "Specify the running guest ID.\n";
    my $guest_name = shift;
    die "Specify the currently applied declaration for the attached adapter.\n"
        if $json->encode($desired) ne $json->encode($before->{desired});
    my ($vf) = grep { $_->{index} == $index } $desired->{vfs}->@*;
    die "Declare the in-use VF index $index.\n" if !$vf;
    if ($vf->{driver} ne 'vfio-pci') {
        die "Specify the interface name in the running container.\n" if !defined($guest_name);
        is($before->{vfs}->[$index]->{ifname}, $guest_name, 'GET locates the moved VF in the container');
        is($json->encode($before->{vfs}->[$index]->{in_container}), 'true', 'GET reports a VF in the container namespace');
    } else {
        is($json->encode($before->{vfs}->[$index]->{in_container}), 'false', 'GET reports false for a VM passthrough VF');
    }
    is_deeply(request('PUT', $desired), $before, 'A running guest permits an identical PUT');
    my $class = $vf->{driver} eq 'vfio-pci' ? 'PVE::QemuConfig' : 'PVE::LXC::Config';
    $class->lock_config($vmid, sub {
        pipe(my $reader, my $writer) or die "Cannot create the lock test pipe: $!\n";
        my $pid = fork() // die "Cannot fork the concurrent API request: $!\n";
        if (!$pid) {
            close($reader);
            eval { request('PUT', $desired) };
            print {$writer} "$@";
            close($writer);
            _exit(0);
        }
        close($writer);
        my $error = do { local $/; <$reader> };
        close($reader);
        waitpid($pid, 0);
        is($?, 0, 'The concurrent API request finished');
        like($error, qr/can't lock file.*\Q$vmid\E.*(?:timed out|timeout)/is,
            'PUT honors the configuration lock used by guest startup');
    });
    my $owner = qr/in use by (?:VM|container) \Q$vmid\E\b/;
    for my $change (
        sub { $_[0]->{numvfs} = 0; $_[0]->{vfs} = [] },
        sub { $_[1]->{mac} = $_[1]->{mac} eq '02:ff:ff:ff:ff:fe' ? '02:ff:ff:ff:ff:fd' : '02:ff:ff:ff:ff:fe' },
        sub { delete $_[1]->{ifname}; $_[1]->{driver} = $_[1]->{driver} eq 'vfio-pci' ? 'iavf' : 'vfio-pci' },
        ($vf->{driver} eq 'vfio-pci' ? () : sub { $_[1]->{ifname} = $_[1]->{ifname} eq 'sriov-check' ? 'sriov-test' : 'sriov-check' }),
    ) {
        my $changed = decode_json($json->encode($desired));
        my ($entry) = grep { $_->{index} == $index } $changed->{vfs}->@*;
        $change->($changed, $entry);
        eval { request('PUT', $changed) };
        like("$@", $owner, 'A running guest prevents a conflicting declaration');
    }
    eval { request('DELETE') };
    like("$@", $owner, 'A running guest prevents DELETE');
    is_deeply(request('GET'), $before, 'Rejected changes preserve runtime and desired state');
} elsif ($mode eq 'mapped') {
    my ($vmid, $key, $selected, $spare, $test_mac) = @ARGV;
    die "Specify the VMID, hostpci property, selected index, spare index, and spare test MAC.\n"
        if !defined($test_mac) || $vmid !~ /\A\d+\z/ || $key !~ /\Ahostpci\d+\z/
        || $selected !~ /\A\d+\z/ || $spare !~ /\A\d+\z/ || $selected == $spare;
    die "The test requires a running VM and its current declaration.\n"
        if !PVE::QemuServer::check_running($vmid, 1)
        || $json->encode($desired) ne $json->encode($before->{desired});
    my $value = PVE::QemuConfig->load_config($vmid)->{$key} // die "Missing $key on VM $vmid.\n";
    my $device = PVE::QemuServer::PCI::parse_hostpci($value);
    my %choices = map { @$_ == 1 ? ($_->[0]->{id} => 1) : () } $device->{ids}->@*;
    my $selected_pci = $before->{vfs}->[$selected]->{pci} // die "Missing selected VF.\n";
    my $spare_pci = $before->{vfs}->[$spare]->{pci} // die "Missing spare VF.\n";
    die "Both VFs must be distinct alternatives of $key.\n" if !$choices{$selected_pci} || !$choices{$spare_pci};
    my $owners = PVE::QemuServer::PCI::get_reservation_owners();
    die "QEMU must own the selected VF and leave the spare unreserved.\n"
        if ($owners->{$selected_pci} // -1) != $vmid || exists($owners->{$spare_pci});
    die "Choose a fresh test MAC outside the current declaration.\n"
        if grep { lc($_->{mac}) eq lc($test_mac) } $desired->{vfs}->@*;
    my $changed_mac = sub {
        my ($index) = @_;
        my $changed = decode_json($json->encode($desired));
        my ($vf) = grep { $_->{index} == $index } $changed->{vfs}->@*;
        die "VF $index must have a declaration.\n" if !$vf;
        $vf->{mac} = $test_mac;
        return $changed;
    };
    my $active_change = $changed_mac->($selected);
    my $spare_change = $changed_mac->($spare);
    eval { request('PUT', $active_change) };
    like("$@", qr/in use by VM \Q$vmid\E\b/, 'PUT rejects a change to the selected mapping');
    eval {
        request('PUT', $spare_change);
        my $actual = request('GET');
        is($actual->{vfs}->[$spare]->{mac}, lc($test_mac), 'PUT changes the unused mapping alternative');
        is_deeply($actual->{vfs}->[$selected], $before->{vfs}->[$selected], 'The selected VF retains its settings');
    };
    my $error = $@;
    request('PUT', $desired);
    die $error if $error;
    is_deeply(request('GET'), $before, 'The spare VF returns to its original configuration');
} else {
    die "Specify unused, attached, or mapped.\n";
}
done_testing();
