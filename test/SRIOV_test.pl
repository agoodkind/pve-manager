#!/usr/bin/perl

use strict;
use warnings;

use lib ('.', '..');

use File::Path qw(make_path);
use File::Temp qw(tempdir);
use Test::More;

use PVE::API2::SRIOV;

my $root = tempdir(CLEANUP => 1);

sub write_file {
    my ($path, $content) = @_;
    open(my $handle, '>', $path) or die "cannot write $path: $!\n";
    print {$handle} $content;
    close($handle) or die "cannot write $path: $!\n";
}

sub read_file {
    my ($path) = @_;
    return '' if !-e $path;
    open(my $handle, '<', $path) or die "cannot read $path: $!\n";
    local $/ = undef;
    my $content = <$handle>;
    close($handle);
    return $content;
}

sub make_port {
    my ($name, $totalvfs, $numvfs) = @_;
    make_path("$root/net/$name/device");
    write_file("$root/net/$name/device/sriov_totalvfs", "$totalvfs\n");
    write_file("$root/net/$name/device/sriov_numvfs", "$numvfs\n");
}

make_port('eth0', 4, 0);
make_port('eth1', 4, 0);
make_path("$root/net/plain0/device");

write_file("$root/allow", "# ports\neth0\n; disabled\n  # indented\n\n");

$PVE::API2::SRIOV::STATE_DIR = "$root/state";
$PVE::API2::SRIOV::ALLOW_FILE = "$root/allow";
$PVE::API2::SRIOV::SYS_NET_DIR = "$root/net";
$PVE::API2::SRIOV::LOCK_DIR = $root;

sub get_port {
    my ($ifname) = @_;
    return PVE::API2::SRIOV->get_sriov({ node => 'localhost', ifname => $ifname });
}

sub put_port {
    my ($ifname, $numvfs, $vfs) = @_;
    my $param = { node => 'localhost', ifname => $ifname };
    $param->{numvfs} = $numvfs if defined($numvfs);
    $param->{vfs} = $vfs if defined($vfs);
    return PVE::API2::SRIOV->set_sriov($param);
}

sub assert_rejected {
    my ($label, $pattern, $ifname, $numvfs, $vfs) = @_;

    eval { put_port($ifname, $numvfs, $vfs) };
    like($@, $pattern, "$label: error message");
    is(read_file("$root/net/eth0/device/sriov_numvfs"), "0\n", "$label: numvfs unchanged");
    ok(!-e "$root/state", "$label: no state written");
}

is_deeply(
    get_port('eth0'),
    { numvfs => 0, totalvfs => 4, vfs => [] },
    'GET returns numvfs, totalvfs, and no VFs for a port without VFs',
);

write_file("$root/net/eth0/device/sriov_numvfs", "0\n");
make_port('eth0', 8, 0);
is(get_port('eth0')->{totalvfs}, 8, 'GET reads totalvfs from sysfs');
make_port('eth0', 4, 0);

for my $invalid ('bad name', 'a' x 16, 'eth0/../eth1') {
    eval { get_port($invalid) };
    like($@, qr/ifname/, "GET rejects the port name '$invalid'");
}
eval { get_port('missing0') };
like($@, qr/Port 'missing0' has no SR-IOV support/, 'GET rejects a port that does not exist');
eval { get_port('plain0') };
like($@, qr/Port 'plain0' has no SR-IOV support/, 'GET rejects a port without sriov_totalvfs');

assert_rejected(
    'port outside the allowlist', qr/Port 'eth1' is not in \Q$root\E\/allow/,
    'eth1', 0, [],
);
assert_rejected(
    'allowlist comment text', qr/ifname/,
    '# ports', 0, [],
);
assert_rejected(
    'numvfs above totalvfs', qr/supports at most 4 virtual functions.*numvfs to 5/,
    'eth0', 5, [],
);
assert_rejected(
    'VF index outside numvfs', qr/VF index 2 is outside 0\.\.1 for numvfs 2/,
    'eth0', 2, [{ index => 2, mac => '02:00:00:00:00:01' }],
);
assert_rejected(
    'repeated VF index', qr/VF index 0 appears more than once/,
    'eth0', 2,
    [{ index => 0, mac => '02:00:00:00:00:01' }, { index => 0, mac => '02:00:00:00:00:02' }],
);
assert_rejected(
    'malformed MAC', qr/VF 0 has the MAC '02:00:00:00:00'.*not six colon-separated hex pairs/,
    'eth0', 1, [{ index => 0, mac => '02:00:00:00:00' }],
);
assert_rejected(
    'multicast MAC', qr/VF 0 has the MAC '03:00:00:00:00:01'.*multicast/,
    'eth0', 1, [{ index => 0, mac => '03:00:00:00:00:01' }],
);
assert_rejected(
    'zero MAC', qr/VF 0 has the MAC '00:00:00:00:00:00'.*all zeros/,
    'eth0', 1, [{ index => 0, mac => '00:00:00:00:00:00' }],
);
assert_rejected(
    'repeated MAC', qr/VF 1 has the MAC '02:aa:bb:cc:dd:ee'.*VF 0 also declares/,
    'eth0', 2,
    [{ index => 0, mac => '02:AA:BB:CC:DD:EE' }, { index => 1, mac => '02:aa:bb:cc:dd:ee' }],
);
assert_rejected(
    'link state outside the enum', qr/link_state/,
    'eth0', 1, [{ index => 0, mac => '02:00:00:00:00:01', link_state => 'up' }],
);
assert_rejected('missing numvfs', qr/numvfs/, 'eth0', undef, []);
assert_rejected(
    'extra VF property', qr/vlan/,
    'eth0', 1, [{ index => 0, mac => '02:00:00:00:00:01', vlan => 5 }],
);

write_file("$root/net/eth0/device/sriov_numvfs", "0\n");
is_deeply(
    get_port('eth0'),
    { numvfs => 0, totalvfs => 4, vfs => [] },
    'rejected requests leave the GET result unchanged',
);

done_testing();
