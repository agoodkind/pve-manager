package PVE::API2::SRIOV;

use strict;
use warnings;

use File::Path qw(make_path);
use JSON qw(decode_json);

use PVE::File;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw(run_command lock_file);

use base qw(PVE::RESTHandler);

use vars qw(
    $STATE_DIR $ALLOW_FILE $SYS_NET_DIR $SYS_PCI_DRIVER_DIR $LOCK_DIR
    $IP_COMMAND $ETHTOOL_COMMAND $SYSTEMCTL_COMMAND
    $SETTLE_ATTEMPTS $SETTLE_INTERVAL
);

$STATE_DIR = '/etc/pve-overlay/sriov';
$ALLOW_FILE = '/etc/pve-overlay/sriov.allow';
$SYS_NET_DIR = '/sys/class/net';
$SYS_PCI_DRIVER_DIR = '/sys/bus/pci/drivers';
$LOCK_DIR = '/run/lock';
$IP_COMMAND = '/sbin/ip';
$ETHTOOL_COMMAND = '/sbin/ethtool';
$SYSTEMCTL_COMMAND = '/bin/systemctl';
$SETTLE_ATTEMPTS = 50;
$SETTLE_INTERVAL = 0.2;

my $STATE_FILE_MODE = 0644;
my $IFNAME_PATTERN = '^[a-zA-Z0-9_.-]{1,15}$';
my $LINK_STATES = ['auto', 'enable', 'disable'];
my $DEFAULT_LINK_STATE = 'auto';
my $MAC_PATTERN = qr/^([0-9a-f]{2}(?::[0-9a-f]{2}){5})\z/;
my $UNICAST_BIT = 0x01;

my $read_names = sub {
    my ($path) = @_;

    return [] if !-e $path;

    my $names = [];
    for my $line (split(/\n/, PVE::File::file_get_contents($path))) {
        $line =~ s/^\s+|\s+$//g;
        next if $line eq '' || $line =~ /^[#;]/;
        push @$names, $line;
    }
    return $names;
};

my $read_sysfs_number = sub {
    my ($path) = @_;

    my $content = PVE::File::file_get_contents($path);
    $content =~ s/^\s+|\s+$//g;
    die "The file $path does not contain a number.\n" if $content !~ /^(\d+)\z/;
    return int($1);
};

my $write_sysfs = sub {
    my ($path, $value) = @_;

    open(my $handle, '>', $path) or die "cannot open $path: $!\n";
    my $written = syswrite($handle, $value);
    my $write_error = $!;
    close($handle) or die "cannot write '$value' to $path: $!\n";
    die "cannot write '$value' to $path: $write_error\n" if !defined($written);
};

my $step_error = sub {
    my ($step, $ifname, $index, $detail) = @_;

    my $where = "port '$ifname'";
    $where = "VF $index of port '$ifname'" if defined($index);
    $detail =~ s/^\s+|\s+$//g;
    die "The SR-IOV step '$step' failed for $where: $detail\n";
};

my $run_step = sub {
    my ($step, $ifname, $index, $command) = @_;

    my $errors = '';
    eval {
        run_command(
            $command,
            outfunc => sub { },
            errfunc => sub { $errors .= shift() . "\n" },
        );
    };
    if ($@) {
        my $detail = $errors;
        $detail = $@ if $detail =~ /^\s*$/;
        $step_error->($step, $ifname, $index, $detail);
    }
};

my $validate_ifname = sub {
    my ($ifname) = @_;

    die "Port name '$ifname' does not match the required pattern $IFNAME_PATTERN.\n"
        if $ifname !~ /^([a-zA-Z0-9_.-]{1,15})\z/;
    my $untainted = $1;

    die "Port '$untainted' has no SR-IOV support: $SYS_NET_DIR/$untainted/device/sriov_totalvfs is missing.\n"
        if !-e "$SYS_NET_DIR/$untainted/device/sriov_totalvfs";

    return $untainted;
};

my $port_dir = sub {
    my ($ifname) = @_;
    return "$SYS_NET_DIR/$ifname/device";
};

my $read_vf_table = sub {
    my ($ifname) = @_;

    my $output = '';
    my $errors = '';
    eval {
        run_command(
            [$IP_COMMAND, 'link', 'show', 'dev', $ifname],
            outfunc => sub { $output .= shift() . "\n" },
            errfunc => sub { $errors .= shift() . "\n" },
        );
    };
    if ($@) {
        my $detail = $errors;
        $detail = $@ if $detail =~ /^\s*$/;
        $step_error->('read', $ifname, undef, $detail);
    }

    my $table = {};
    for my $line (split(/\n/, $output)) {
        next if $line !~ /^\s*vf (\d+)\s+.*?link\/ether ([0-9a-fA-F:]{17})\b(.*)$/;
        my ($index, $mac, $rest) = (int($1), lc($2), $3);
        my $link_state = $DEFAULT_LINK_STATE;
        $link_state = $1 if $rest =~ /link-state (auto|enable|disable)/;
        $table->{$index} = { mac => $mac, link_state => $link_state };
    }
    return $table;
};

my $read_vf_device = sub {
    my ($ifname, $index) = @_;

    my $device_path = $port_dir->($ifname) . "/virtfn$index";
    return undef if !-e $device_path;

    my $address = '';
    my $address_target = readlink($device_path);
    if (defined($address_target) && $address_target =~ m{([0-9a-fA-F:.]+)\z}) {
        $address = $1;
    }

    my $driver = '';
    my $driver_target = readlink("$device_path/driver");
    if (defined($driver_target) && $driver_target =~ m{([A-Za-z0-9_.-]+)\z}) {
        $driver = $1;
    }

    my $netdev = '';
    if (opendir(my $directory, "$device_path/net")) {
        my @names = sort grep { !/^\./ } readdir($directory);
        closedir($directory);
        $netdev = $1 if @names && $names[0] =~ /^([a-zA-Z0-9_.-]{1,15})\z/;
    }

    return { address => $address, driver => $driver, ifname => $netdev };
};

my $read_state = sub {
    my ($ifname) = @_;

    my $numvfs = $read_sysfs_number->($port_dir->($ifname) . '/sriov_numvfs');
    my $totalvfs = $read_sysfs_number->($port_dir->($ifname) . '/sriov_totalvfs');

    my $vfs = [];
    if ($numvfs > 0) {
        my $table = $read_vf_table->($ifname);
        for my $index (0 .. $numvfs - 1) {
            my $entry = $table->{$index} // {};
            my $device = $read_vf_device->($ifname, $index) // {};
            push @$vfs, {
                index => $index,
                mac => $entry->{mac} // '',
                link_state => $entry->{link_state} // $DEFAULT_LINK_STATE,
                ifname => $device->{ifname} // '',
                driver => $device->{driver} // '',
            };
        }
    }

    return { numvfs => $numvfs, totalvfs => $totalvfs, vfs => $vfs };
};

my $validate_declaration = sub {
    my ($ifname, $numvfs, $vfs) = @_;

    my $totalvfs = $read_sysfs_number->($port_dir->($ifname) . '/sriov_totalvfs');
    die "Port '$ifname' supports at most $totalvfs virtual functions, and the request sets numvfs to $numvfs.\n"
        if $numvfs < 0 || $numvfs > $totalvfs;

    my $normalized = [];
    my $seen_indexes = {};
    my $seen_macs = {};
    for my $vf (@$vfs) {
        my $index = $vf->{index};
        die "VF index $index is outside 0..", $numvfs - 1, " for numvfs $numvfs on port '$ifname'.\n"
            if $index < 0 || $index >= $numvfs;
        die "VF index $index appears more than once.\n" if $seen_indexes->{$index}++;

        my $requested_mac = lc($vf->{mac});
        die "VF $index has the MAC '$vf->{mac}', which is not six colon-separated hex pairs.\n"
            if $requested_mac !~ $MAC_PATTERN;
        my $mac = $1;
        my $first_byte = hex(substr($mac, 0, 2));
        die "VF $index has the MAC '$mac', which is a multicast address.\n"
            if $first_byte & $UNICAST_BIT;
        die "VF $index has the MAC '$mac', which is all zeros.\n" if $mac eq '00:00:00:00:00:00';
        die "VF $index has the MAC '$mac', which VF $seen_macs->{$mac} also declares.\n"
            if defined($seen_macs->{$mac});
        $seen_macs->{$mac} = $index;

        my $link_state = $vf->{link_state} // $DEFAULT_LINK_STATE;
        die "VF $index has the link_state '$link_state', which is not auto, enable, or disable.\n"
            if !grep { $_ eq $link_state } @$LINK_STATES;

        push @$normalized, { index => int($index), mac => $mac, link_state => $link_state };
    }

    return [sort { $a->{index} <=> $b->{index} } @$normalized];
};

my $settle = sub {
    my ($condition) = @_;

    for my $attempt (1 .. $SETTLE_ATTEMPTS) {
        return 1 if $condition->();
        select(undef, undef, undef, $SETTLE_INTERVAL);
    }
    return $condition->() ? 1 : 0;
};

my $set_numvfs = sub {
    my ($ifname, $numvfs) = @_;

    my $path = $port_dir->($ifname) . '/sriov_numvfs';
    my $current = $read_sysfs_number->($path);
    return if $current == $numvfs;

    eval {
        $write_sysfs->($path, '0');
        $write_sysfs->($path, "$numvfs") if $numvfs > 0;
    };
    $step_error->('set numvfs', $ifname, undef, $@) if $@;

    my $read_back = $read_sysfs_number->($path);
    $step_error->(
        'verify numvfs', $ifname, undef,
        "sriov_numvfs reads $read_back after the write of $numvfs",
    ) if $read_back != $numvfs;

    for my $index (0 .. $numvfs - 1) {
        my $present = $settle->(sub { -e $port_dir->($ifname) . "/virtfn$index" });
        $step_error->(
            'wait for VF', $ifname, $index,
            "virtfn$index did not appear after the write of $numvfs",
        ) if !$present;
    }
};

my $rebind_vf = sub {
    my ($ifname, $index) = @_;

    my $device = $read_vf_device->($ifname, $index);
    $step_error->('rebind', $ifname, $index, "virtfn$index does not exist")
        if !defined($device);
    $step_error->('rebind', $ifname, $index, "virtfn$index has no PCI address or no driver")
        if $device->{address} eq '' || $device->{driver} eq '';

    my $driver_dir = "$SYS_PCI_DRIVER_DIR/$device->{driver}";
    eval {
        $write_sysfs->("$driver_dir/unbind", $device->{address});
        $write_sysfs->("$driver_dir/bind", $device->{address});
    };
    $step_error->('rebind', $ifname, $index, $@) if $@;
};

my $permanent_mac = sub {
    my ($netdev) = @_;

    my $output = '';
    my $errors = '';
    eval {
        run_command(
            [$ETHTOOL_COMMAND, '-P', $netdev],
            outfunc => sub { $output .= shift() . "\n" },
            errfunc => sub { $errors .= shift() . "\n" },
        );
    };
    return (undef, $errors) if $@;
    return (lc($1), $errors) if $output =~ /Permanent address:\s*([0-9a-fA-F:]{17})/;
    return (undef, "ethtool -P printed no permanent address: $output");
};

my $verify_vf_mac = sub {
    my ($ifname, $vf) = @_;

    my $index = $vf->{index};
    my $netdev = '';
    my $found = $settle->(sub {
        my $device = $read_vf_device->($ifname, $index);
        $netdev = $device->{ifname} // '' if defined($device);
        return $netdev ne '';
    });
    $step_error->('verify mac', $ifname, $index, "virtfn$index has no network device after the rebind")
        if !$found;

    my $reported = '';
    my $detail = '';
    my $matched = $settle->(sub {
        my ($mac, $errors) = $permanent_mac->($netdev);
        $detail = $errors;
        $reported = $mac // '';
        return $reported eq $vf->{mac};
    });
    if (!$matched) {
        my $message = "$netdev reports permanent address '$reported', and the declaration is '$vf->{mac}'";
        $message .= ": $detail" if $detail !~ /^\s*$/;
        $step_error->('verify mac', $ifname, $index, $message);
    }
};

my $apply_declaration = sub {
    my ($ifname, $numvfs, $vfs) = @_;

    $run_step->('port up', $ifname, undef, [$IP_COMMAND, 'link', 'set', $ifname, 'up']);

    $set_numvfs->($ifname, $numvfs);

    for my $vf (@$vfs) {
        my $index = $vf->{index};
        $run_step->(
            'set mac', $ifname, $index,
            [$IP_COMMAND, 'link', 'set', $ifname, 'vf', "$index", 'mac', $vf->{mac}],
        );
        $run_step->(
            'set link state', $ifname, $index,
            [$IP_COMMAND, 'link', 'set', $ifname, 'vf', "$index", 'state', $vf->{link_state}],
        );
    }

    for my $vf (@$vfs) {
        $rebind_vf->($ifname, $vf->{index});
    }

    for my $vf (@$vfs) {
        $verify_vf_mac->($ifname, $vf);
    }
};

my $state_path = sub {
    my ($ifname) = @_;
    return "$STATE_DIR/$ifname.json";
};

my $with_lock = sub {
    my ($ifname, $code) = @_;

    my $result = lock_file("$LOCK_DIR/pve-overlay-sriov-$ifname.lck", 60, $code);
    die $@ if $@;
    return $result;
};

sub apply_saved {
    my ($class, $ifname_input) = @_;

    my $ifname = $validate_ifname->($ifname_input);
    my $path = $state_path->($ifname);
    die "The saved SR-IOV state $path does not exist.\n" if !-e $path;

    my $saved = eval { decode_json(PVE::File::file_get_contents($path)) };
    die "The saved SR-IOV state $path is not valid JSON: $@" if $@;
    die "The saved SR-IOV state $path has no numvfs.\n"
        if ref($saved) ne 'HASH' || !defined($saved->{numvfs}) || $saved->{numvfs} !~ /^\d+\z/;

    my $vfs = $validate_declaration->($ifname, int($saved->{numvfs}), $saved->{vfs} // []);
    $with_lock->($ifname, sub { $apply_declaration->($ifname, int($saved->{numvfs}), $vfs) });

    return $read_state->($ifname);
}

my $state_returns = {
    type => 'object',
    properties => {
        numvfs => { type => 'integer', minimum => 0, description => 'PROSE' },
        totalvfs => { type => 'integer', minimum => 0, description => 'PROSE' },
        vfs => {
            type => 'array',
            description => 'PROSE',
            items => {
                type => 'object',
                properties => {
                    index => { type => 'integer', minimum => 0, description => 'PROSE' },
                    mac => { type => 'string', description => 'PROSE' },
                    link_state => {
                        type => 'string',
                        enum => $LINK_STATES,
                        description => 'PROSE',
                    },
                    ifname => { type => 'string', description => 'PROSE' },
                    driver => { type => 'string', description => 'PROSE' },
                },
            },
        },
    },
};

my $ifname_schema = {
    type => 'string',
    pattern => $IFNAME_PATTERN,
    maxLength => 15,
    description => 'PROSE',
};

__PACKAGE__->register_method({
    name => 'get_sriov',
    path => '{ifname}',
    method => 'GET',
    description => 'PROSE',
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.SRIOV.Audit']],
    },
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            ifname => $ifname_schema,
        },
    },
    returns => $state_returns,
    code => sub {
        my ($param) = @_;

        my $ifname = $validate_ifname->($param->{ifname});
        return $read_state->($ifname);
    },
});

__PACKAGE__->register_method({
    name => 'set_sriov',
    path => '{ifname}',
    method => 'PUT',
    description => 'PROSE',
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.SRIOV.Modify']],
    },
    protected => 1,
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            ifname => $ifname_schema,
            numvfs => {
                type => 'integer',
                minimum => 0,
                description => 'PROSE',
            },
            vfs => {
                type => 'array',
                optional => 1,
                description => 'PROSE',
                items => {
                    type => 'object',
                    additionalProperties => 0,
                    properties => {
                        index => { type => 'integer', minimum => 0, description => 'PROSE' },
                        mac => { type => 'string', description => 'PROSE' },
                        link_state => {
                            type => 'string',
                            enum => $LINK_STATES,
                            optional => 1,
                            default => $DEFAULT_LINK_STATE,
                            description => 'PROSE',
                        },
                    },
                },
            },
        },
    },
    returns => $state_returns,
    code => sub {
        my ($param) = @_;

        my $ifname = $validate_ifname->($param->{ifname});

        my $allowed = { map { $_ => 1 } @{ $read_names->($ALLOW_FILE) } };
        die "Port '$ifname' is not in $ALLOW_FILE.\n" if !$allowed->{$ifname};

        my $numvfs = int($param->{numvfs});
        my $vfs = $validate_declaration->($ifname, $numvfs, $param->{vfs} // []);

        $with_lock->($ifname, sub { $apply_declaration->($ifname, $numvfs, $vfs) });

        make_path($STATE_DIR);
        my $content = JSON->new->canonical->pretty->encode({ numvfs => $numvfs, vfs => $vfs });
        PVE::File::file_set_contents($state_path->($ifname), $content, $STATE_FILE_MODE);

        $run_step->(
            'enable unit', $ifname, undef,
            [$SYSTEMCTL_COMMAND, 'enable', "pve-overlay-sriov\@$ifname.service"],
        );

        return $read_state->($ifname);
    },
});

1;
