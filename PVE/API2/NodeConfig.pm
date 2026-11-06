package PVE::API2::NodeConfig;

use strict;
use warnings;

use PVE::Exception qw(raise_perm_exc);
use PVE::JSONSchema qw(get_standard_option);
use PVE::NodeConfig;
use PVE::RPCEnvironment;
use PVE::Tools qw(extract_param);

use base qw(PVE::RESTHandler);

my $acme_domain_key_re = qr/^acmedomain\d+$/;

# Returns the scoped privilege that authorizes a change to one node config key,
# or undef for a key that only Sys.Modify on / may change.
my $acme_key_privilege = sub {
    my ($key, $is_delete) = @_;

    return 'Sys.ACME.Config.Account.Modify' if $key eq 'acme';
    return undef if $key !~ $acme_domain_key_re;
    return $is_delete ? 'Sys.ACME.Config.Domain.Remove' : 'Sys.ACME.Config.Domain.Modify';
};

# Checks a request from a user without Sys.Modify on /. Every changed key must
# be an ACME key, and the user needs the scoped privilege for that change on
# the node.
my $check_scoped_change = sub {
    my ($rpcenv, $authuser, $node, $set_keys, $deleted_keys) = @_;

    raise_perm_exc("/, Sys.Modify") if !@$set_keys && !@$deleted_keys;

    for my $change ((map { [$_, 0] } @$set_keys), (map { [$_, 1] } @$deleted_keys)) {
        my $privilege = $acme_key_privilege->(@$change) // raise_perm_exc("/, Sys.Modify");
        $rpcenv->check($authuser, "/nodes/$node", [$privilege]);
    }
};

my $node_config_schema = PVE::NodeConfig::get_nodeconfig_schema();
my $node_config_keys = [sort keys %$node_config_schema];
my $node_config_return_properties = {
    digest => {
        type => 'string',
        description =>
            'Prevent changes if current configuration file has different SHA1 digest. This can be used to prevent concurrent modifications.',
        maxLength => 40,
        optional => 1,
    },
    %$node_config_schema,
};
my $node_config_properties = {
    delete => {
        type => 'string',
        format => 'pve-configid-list',
        description => "A list of settings you want to delete.",
        optional => 1,
    },
    node => get_standard_option('pve-node'),
    %$node_config_return_properties,
};

__PACKAGE__->register_method({
    name => 'get_config',
    path => '',
    method => 'GET',
    description => "Get node configuration options.",
    permissions => {
        description => "Requires Sys.Audit on /. With Sys.ACME.Config.Audit on"
            . " /nodes/{node}, only the 'acme' and 'acmedomain' options are returned.",
        user => 'all',
    },
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            property => {
                type => 'string',
                description => 'Return only a specific property from the node configuration.',
                enum => $node_config_keys,
                optional => 1,
                default => 'all',
            },
        },
    },
    returns => {
        type => "object",
        properties => $node_config_return_properties,
    },
    code => sub {
        my ($param) = @_;

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();
        my $node = $param->{node};

        my $reads_all_keys =
            $authuser eq 'root@pam' || $rpcenv->check($authuser, '/', ['Sys.Audit'], 1);
        $rpcenv->check($authuser, "/nodes/$node", ['Sys.ACME.Config.Audit'])
            if !$reads_all_keys;

        my $config = PVE::NodeConfig::load_config($node);

        if (!$reads_all_keys) {
            for my $key (keys %$config) {
                next if $key eq 'digest' || $key eq 'acme' || $key =~ $acme_domain_key_re;
                delete $config->{$key};
            }
        }

        if (defined(my $prop = $param->{property})) {
            return {} if !exists $config->{$prop};
            return { $prop => $config->{$prop} };
        }

        return $config;
    },
});

__PACKAGE__->register_method({
    name => 'set_options',
    path => '',
    method => 'PUT',
    description => "Set node configuration options.",
    permissions => {
        description => "Requires Sys.Modify on /. A request that changes only 'acme' and"
            . " 'acmedomain' options requires the matching Sys.ACME.Config privilege on"
            . " /nodes/{node}.",
        user => 'all',
    },
    protected => 1,
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => $node_config_properties,
    },
    returns => { type => "null" },
    code => sub {
        my ($param) = @_;

        my $delete = extract_param($param, 'delete');
        my $node = extract_param($param, 'node');
        my $digest = extract_param($param, 'digest');

        my $rpcenv = PVE::RPCEnvironment::get();
        my $authuser = $rpcenv->get_user();
        my $changes_all_keys =
            $authuser eq 'root@pam' || $rpcenv->check($authuser, '/', ['Sys.Modify'], 1);
        if (!$changes_all_keys) {
            my $deleted_keys = [PVE::Tools::split_list($delete // '')];
            $check_scoped_change->($rpcenv, $authuser, $node, [keys %$param], $deleted_keys);
        }

        my $code = sub {
            my $conf = PVE::NodeConfig::load_config($node);

            PVE::Tools::assert_if_modified($digest, $conf->{digest});

            foreach my $opt (sort keys %$param) {
                $conf->{$opt} = $param->{$opt};
            }

            foreach my $opt (PVE::Tools::split_list($delete)) {
                delete $conf->{$opt};
            }

            PVE::NodeConfig::verify_conf($conf);
            PVE::NodeConfig::write_config($node, $conf);
        };

        PVE::NodeConfig::lock_config($node, $code);
        die $@ if $@;

        return undef;
    },
});

1;
