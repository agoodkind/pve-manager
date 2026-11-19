#!/usr/bin/perl

use strict;
use warnings;

use Test::More;
use PVE::API2::SRIOV;

sub request {
    my ($method, $ifname, $body) = @_;
    my $param = { node => 'localhost', %{ $body // {} } };
    my ($handler, $info) = PVE::API2::SRIOV->find_handler($method, $ifname, $param);
    die "$method $ifname did not resolve to a Proxmox API handler.\n" if !$handler;
    return $handler->handle($info, $param, 1);
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
done_testing();
