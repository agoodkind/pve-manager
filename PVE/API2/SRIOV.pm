package PVE::API2::SRIOV;

use strict;
use warnings;

use PVE::JSONSchema qw(get_standard_option);
use PVE::SRIOV;

use base qw(PVE::RESTHandler);

my $port = {
    node => get_standard_option('pve-node'),
    ifname => PVE::SRIOV::ifname_schema(),
};
my $declaration = PVE::SRIOV::declaration_schema();
my $state = {
    type => 'object',
    properties => {
        numvfs => { type => 'integer', description => 'Number of enabled virtual functions.' },
        totalvfs => { type => 'integer', description => 'Maximum number of virtual functions.' },
        desired => { %$declaration, optional => 1 },
        vfs => {
            type => 'array',
            items => {
                type => 'object',
                properties => {
                    index => { type => 'integer', description => 'Virtual function index.' },
                    mac => { type => 'string', description => 'MAC address on the physical function.' },
                    pci => { type => 'string', description => 'PCI domain, bus, slot, and function.' },
                    driver => { type => 'string', optional => 1, description => 'Bound PCI driver.' },
                    ifname => { type => 'string', optional => 1, description => 'Current Linux interface name in the host or container.' },
                },
            },
        },
    },
};

__PACKAGE__->register_method({
    name => 'get_sriov',
    path => '{ifname}',
    method => 'GET',
    description => 'Read the saved declaration and current virtual functions of a network adapter.',
    permissions => { check => ['perm', '/nodes/{node}', ['Sys.SRIOV.Audit']] },
    protected => 1,
    proxyto => 'node',
    parameters => { additionalProperties => 0, properties => $port },
    returns => $state,
    code => sub {
        my ($param) = @_;
        return PVE::SRIOV::get_port($param->{ifname});
    },
});

__PACKAGE__->register_method({
    name => 'set_sriov',
    path => '{ifname}',
    method => 'PUT',
    description => 'Apply and save the virtual function count and configuration of a network adapter.',
    permissions => { check => ['perm', '/nodes/{node}', ['Sys.SRIOV.Modify']] },
    protected => 1,
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => { %$port, $declaration->{properties}->%* },
    },
    returns => $state,
    code => sub {
        my ($param) = @_;
        return PVE::SRIOV::set_port($param->{ifname}, {
            numvfs => $param->{numvfs}, vfs => $param->{vfs},
        });
    },
});

__PACKAGE__->register_method({
    name => 'delete_sriov',
    path => '{ifname}',
    method => 'DELETE',
    description => 'Disable the virtual functions and delete the saved declaration for a managed adapter.',
    permissions => { check => ['perm', '/nodes/{node}', ['Sys.SRIOV.Modify']] },
    protected => 1,
    proxyto => 'node',
    parameters => { additionalProperties => 0, properties => $port },
    returns => { type => 'null' },
    code => sub {
        my ($param) = @_;
        PVE::SRIOV::delete_port($param->{ifname});
        return undef;
    },
});

1;
