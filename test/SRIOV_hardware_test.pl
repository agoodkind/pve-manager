#!/usr/bin/perl

use strict;
use warnings;

use JSON qw(decode_json);
use POSIX qw(_exit);
use Test::More;
use PVE::API2::SRIOV;
use PVE::File;
use PVE::Tools qw(run_command);

my $mode = shift // die "Specify unused or attached.\n";
my $port = shift // die "Specify the dedicated physical interface.\n";
my $path = shift // die "Specify the JSON declaration file.\n";
my $desired = decode_json(PVE::File::file_get_contents($path));
my $json = JSON->new->canonical;
my $node = PVE::INotify::nodename();

sub request {
    my ($method, $body) = @_;
    my $param = { node => $node, %{ $body // {} } };
    my ($handler, $info) = PVE::API2::SRIOV->find_handler($method, $port, $param);
    die "Cannot resolve $method for $port.\n" if !$handler;
    return $handler->handle($info, $param, 1);
}

my $before = request('GET');
if ($mode eq 'unused') {
    die "This test requires a dedicated unmanaged adapter with zero enabled VFs.\n"
        if $before->{numvfs} || exists($before->{desired});
    die "Declare at least one VF and a positive VF count.\n" if !@{ $desired->{vfs} } || !$desired->{numvfs};
    my $reserve_id = shift // die "Specify an unused VMID for the pending PCI reservation test.\n";
    die "The reservation test requires an unused VMID.\n"
        if $reserve_id !~ /\A\d+\z/ || PVE::Cluster::get_vmlist()->{ids}->{$reserve_id};
    my $after = request('PUT', $desired);
    is($after->{numvfs}, $desired->{numvfs}, 'PUT enables the requested number of VFs');
    for my $vf ($desired->{vfs}->@*) {
        my $actual = $after->{vfs}->[$vf->{index}];
        is($actual->{driver}, $vf->{driver}, "VF $vf->{index} binds to the declared driver");
        is($actual->{mac}, lc($vf->{mac}), "VF $vf->{index} uses the declared MAC");
        like($actual->{pci}, qr/\A[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-7]\z/, 'GET reports the PCI address');
        is($actual->{ifname}, $vf->{ifname}, 'The network driver uses the stable name') if defined($vf->{ifname});
    }
    is_deeply(request('PUT', $desired), $after, 'Repeated PUT preserves runtime and desired state');
    my $pci = $after->{vfs}->[$desired->{vfs}->[0]->{index}]->{pci};
    PVE::QemuServer::PCI::reserve_pci_usage($pci, $reserve_id, 30);
    eval { request('DELETE') };
    my $reserve_error = "$@";
    PVE::QemuServer::PCI::remove_pci_reservation($reserve_id, [$pci]);
    like($reserve_error, qr/in use by VM \Q$reserve_id\E\b/, 'A PCI reservation protects the VF before QEMU publishes its PID');
    run_command(['/bin/systemctl', 'restart', 'pve-overlay-sriov.service']);
    is_deeply(request('GET'), $after, 'Boot restoration preserves the declaration');
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
} else {
    die "Specify unused or attached.\n";
}
done_testing();
