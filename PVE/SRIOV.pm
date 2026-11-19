package PVE::SRIOV;

use strict;
use warnings;

use Errno qw(ENOENT);
use Fcntl qw(O_WRONLY);
use File::Basename qw(basename);
use File::Path qw(make_path);
use JSON qw(decode_json);

use PVE::Cluster;
use PVE::File;
use PVE::INotify;
use PVE::JSONSchema;
use PVE::LXC;
use PVE::LXC::Config;
use PVE::QemuConfig;
use PVE::QemuServer;
use PVE::QemuServer::PCI;
use PVE::Tools qw(lock_file run_command);

my $state_dir = '/etc/pve-overlay/sriov';
my $lock = '/run/lock/pve-overlay-sriov.lock';
my $pci_root = '/sys/bus/pci';
my $name_pattern = '[a-zA-Z0-9_][a-zA-Z0-9_.-]{0,14}';
my $driver_pattern = '[a-zA-Z0-9_][a-zA-Z0-9_-]{0,63}';
my $pci_pattern = '[[:xdigit:]]{4}:[[:xdigit:]]{2}:[[:xdigit:]]{2}\.[0-7]';
my $json = JSON->new->canonical;

sub ifname_schema {
    return { type => 'string', pattern => "^$name_pattern\$", description => 'Linux interface name.' };
}

sub declaration_schema {
    return {
        type => 'object',
        additionalProperties => 0,
        properties => {
            numvfs => { type => 'integer', minimum => 0, description => 'Number of virtual functions to enable.' },
            vfs => {
                type => 'array',
                items => {
                    type => 'object',
                    additionalProperties => 0,
                    properties => {
                        index => { type => 'integer', minimum => 0, description => 'Hardware virtual function index.' },
                        mac => { type => 'string', pattern => '^([[:xdigit:]]{2}:){5}[[:xdigit:]]{2}$', description => 'Unicast MAC address.' },
                        driver => { type => 'string', pattern => "^$driver_pattern\$", description => 'Native VF network driver or vfio-pci.' },
                        ifname => { %{ ifname_schema() }, optional => 1 },
                    },
                },
            },
        },
    };
}

sub port_name {
    my ($value) = @_;
    die "Invalid Linux interface name '$value'.\n" if $value !~ /\A($name_pattern)\z/;
    return $1;
}

sub sys_value {
    my ($path) = @_;
    my $text = PVE::File::file_get_contents($path);
    chomp $text;
    return $text;
}

sub number {
    my ($path) = @_;
    my $value = sys_value($path);
    die "Invalid integer in $path.\n" if $value !~ /\A(\d+)\z/;
    return int($1);
}

sub pf_device {
    my ($name) = @_;
    my $path = "/sys/class/net/$name";
    die "Network interface '$name' does not exist.\n" if !-d $path;
    die "Interface '$name' does not support SR-IOV.\n" if !-f "$path/device/sriov_totalvfs";
    return "$path/device";
}

sub write_attribute {
    my ($path, $value) = @_;
    sysopen(my $file, $path, O_WRONLY) or die "Cannot open $path: $!\n";
    my $len = syswrite($file, $value);
    die "Cannot write '$value' to $path: $!\n" if !defined($len) || $len != length($value);
    close($file) or die "Cannot close $path: $!\n";
}

sub output {
    my ($cmd) = @_;
    my $text = '';
    run_command($cmd, outfunc => sub { $text .= shift() . "\n" });
    return $text;
}

sub entries {
    my ($path) = @_;
    opendir(my $dir, $path) or die "Cannot open $path: $!\n";
    my @names = sort grep { $_ ne '.' && $_ ne '..' } readdir($dir);
    closedir($dir) or die "Cannot close $path: $!\n";
    return @names;
}

sub driver_name {
    my ($path) = @_;
    my $target = readlink("$path/driver");
    return undef if !defined($target) && $! == ENOENT;
    die "Cannot read $path/driver: $!\n" if !defined($target);
    my $name = basename($target);
    die "Invalid driver at $path: $name\n" if $name !~ /\A($driver_pattern)\z/;
    return $1;
}

sub local_guests {
    PVE::Cluster::cfs_update();
    my $node = PVE::INotify::nodename();
    my $ids = PVE::Cluster::get_vmlist()->{ids};
    return { map { $_ => $ids->{$_}->{type} } grep { $ids->{$_}->{node} eq $node } keys %$ids };
}

# Guest start and device hotplug use the same per-guest configuration locks.
sub with_guest_locks {
    my ($guests, $ids, $operation) = @_;
    return $operation->() if !@$ids;
    my $id = shift @$ids;
    my $class = $guests->{$id} eq 'qemu' ? 'PVE::QemuConfig' : 'PVE::LXC::Config';
    return $class->lock_config($id, sub { with_guest_locks($guests, $ids, $operation) });
}

sub inspect_guest {
    my ($id, $type, $by_pci, $by_link, $owners, $netns) = @_;
    if ($type eq 'qemu') {
        return if !PVE::QemuServer::check_running($id, 1);
        my @addresses = PVE::QemuServer::PCI::get_reservations($id)->@*;
        my $config = PVE::QemuConfig->load_config($id);
        for my $key (grep { /\Ahostpci\d+\z/ } keys %$config) {
            my $device = PVE::QemuServer::PCI::parse_hostpci($config->{$key});
            for my $alternative ($device->{ids}->@*) {
                push @addresses, map { $_->{id} } @$alternative;
            }
        }
        for my $address (@addresses) {
            $owners->{$address} = "VM $id" if exists($by_pci->{$address});
        }
        return;
    }

    die "Unsupported local guest type '$type'.\n" if $type ne 'lxc';
    return if !PVE::LXC::check_running($id);
    my $config = PVE::LXC::Config->load_config($id);
    my $hostnics = PVE::LXC::Config->get_hostnics($config);
    for my $nic (values %$hostnics) {
        my $address = $by_link->{$nic->{link}};
        $owners->{$address} = "container $id" if defined($address);
    }

    return if !grep { defined($_->{driver}) && $_->{driver} ne 'vfio-pci' && !defined($_->{ifname}) } values %$by_pci;
    my $pid = PVE::LXC::find_lxc_pid($id);
    my @ns = ('/usr/bin/nsenter', '--target', $pid, '--net', '--');
    my $links = decode_json(output([@ns, '/sbin/ip', '-j', '-d', 'link', 'show']));
    for my $link (@$links) {
        next if grep { $_ eq 'LOOPBACK' } $link->{flags}->@*;
        my $name = port_name($link->{ifname});
        my $bus = $link->{parentdev};
        if (!defined($bus)) {
            next if defined($link->{linkinfo}->{info_kind});
            my $info = output([@ns, '/sbin/ethtool', '-i', $name]);
            ($bus) = $info =~ /^bus-info:\s*($pci_pattern)$/m;
        }
        next if !defined($bus) || !exists($by_pci->{$bus});
        $by_pci->{$bus}->{ifname} = $name;
        $netns->{$bus} = $pid;
        $owners->{$bus} = "container $id";
    }
}

sub saved {
    my ($name) = @_;
    my $path = "$state_dir/$name.json";
    return undef if !-e $path;
    my $data = decode_json(PVE::File::file_get_contents($path));
    PVE::JSONSchema::validate($data, declaration_schema());
    return $data;
}

sub observe {
    my ($name, $desired, $guests) = @_;
    my $pf = pf_device($name);
    my $count = number("$pf/sriov_numvfs");
    my $state = { numvfs => $count, totalvfs => number("$pf/sriov_totalvfs"), vfs => [] };
    $state->{desired} = $desired if defined($desired);
    my (%owners, %netns);
    return ($state, \%owners, \%netns) if !$count;
    my $links = decode_json(output(['/sbin/ip', '-j', '-d', 'link', 'show', 'dev', $name]));
    my %macs = map { $_->{vf} => $_->{mac} } $links->[0]->{vfinfo_list}->@*;
    my (%by_pci, %by_link);
    for my $index (0 .. $count - 1) {
        my $path = "$pf/virtfn$index";
        my $target = readlink($path) // die "Cannot read $path: $!\n";
        my ($pci) = $target =~ m{/($pci_pattern)\z};
        die "Invalid PCI address in $path: $target\n" if !defined($pci);
        my $mac = $macs{$index} // die "The adapter did not report a MAC for VF $index on $name.\n";
        my $vf = { index => $index, pci => $pci, mac => lc($mac) };
        my $driver = driver_name($path);
        $vf->{driver} = $driver if defined($driver);
        my @interfaces = -d "$path/net" ? entries("$path/net") : ();
        die "VF $index on $name has several Linux interfaces.\n" if @interfaces > 1;
        if (@interfaces) {
            $vf->{ifname} = port_name($interfaces[0]);
            $by_link{$vf->{ifname}} = $pci;
        }
        push $state->{vfs}->@*, $vf;
        $by_pci{$pci} = $vf;
    }
    for my $vf (@{ $desired->{vfs} // [] }) {
        next if !defined($vf->{ifname}) || $vf->{index} >= $count;
        $by_link{$vf->{ifname}} = $state->{vfs}->[$vf->{index}]->{pci};
    }
    for my $id (sort { $a <=> $b } keys %$guests) {
        inspect_guest($id, $guests->{$id}, \%by_pci, \%by_link, \%owners, \%netns);
    }
    return ($state, \%owners, \%netns);
}

sub normalize {
    my ($name, $request, $total) = @_;
    PVE::JSONSchema::validate($request, declaration_schema());
    my $count = int($request->{numvfs});
    die "Interface $name supports $total VFs, fewer than the requested $count.\n" if $count > $total;
    my (%indices, %macs, %names);
    my @vfs;
    for my $item ($request->{vfs}->@*) {
        my $index = int($item->{index});
        die "VF index $index exceeds the requested count $count.\n" if $index >= $count;
        die "Duplicate VF index $index.\n" if $indices{$index}++;
        my ($mac) = lc($item->{mac}) =~ /\A((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\z/;
        die "Invalid unicast MAC address '$item->{mac}'.\n" if !defined($mac)
            || hex(substr($mac, 0, 2)) & 1 || $mac eq '00:00:00:00:00:00';
        die "Duplicate VF MAC address $mac.\n" if $macs{$mac}++;
        my ($driver) = $item->{driver} =~ /\A($driver_pattern)\z/;
        die "Invalid VF driver.\n" if !defined($driver);
        my $vf = { index => $index, mac => $mac, driver => $driver };
        if (defined($item->{ifname})) {
            my $ifname = port_name($item->{ifname});
            die "Driver vfio-pci does not provide a Linux interface.\n" if $driver eq 'vfio-pci';
            die "Interface name '$ifname' is already in use in this declaration.\n"
                if $ifname eq $name || $ifname eq 'lo' || $names{$ifname}++;
            $vf->{ifname} = $ifname;
        }
        push @vfs, $vf;
    }
    return { numvfs => $count, vfs => [sort { $a->{index} <=> $b->{index} } @vfs] };
}

sub wait_until {
    my ($description, $check) = @_;
    for (1 .. 100) {
        return if $check->();
        select(undef, undef, undef, 0.1);
    }
    die "Timed out waiting for $description.\n";
}

sub prepare_driver {
    my ($path, $driver) = @_;
    if ($driver ne 'vfio-pci') {
        my $alias = sys_value("$path/modalias");
        die "Invalid PCI modalias at $path.\n" if $alias !~ /\A(pci:[a-zA-Z0-9]+)\z/;
        my $matches = output(['/sbin/modprobe', '--resolve-alias', '--', $1]);
        my $module = $driver =~ tr/-/_/r;
        die "Driver '$driver' does not match the PCI device at $path.\n"
            if !grep { $_ eq $module } split(/\n/, $matches);
    }
    run_command(['/sbin/modprobe', '--', $driver]);
    die "Kernel module '$driver' does not provide PCI driver '$driver'.\n"
        if !-d "$pci_root/drivers/$driver";
}

sub permanent_mac {
    my ($current, $netns) = @_;
    my $name = $current->{ifname} // die "PCI device $current->{pci} does not expose a network interface.\n";
    my $pid = $netns->{$current->{pci}};
    my @prefix = defined($pid) ? ('/usr/bin/nsenter', '--target', $pid, '--net', '--') : ();
    my $output = output([@prefix, '/sbin/ethtool', '-P', $name]);
    my ($mac) = $output =~ /^Permanent address:\s*([[:xdigit:]]{2}(?::[[:xdigit:]]{2}){5})$/m;
    die "Interface $name on $current->{pci} did not report its permanent MAC: $output" if !defined($mac);
    return lc($mac);
}

sub change_vf {
    my ($name, $current, $vf, $refresh_mac) = @_;
    my $path = "$pci_root/devices/$current->{pci}";
    my $driver = $vf->{driver};
    prepare_driver($path, $driver);
    my $mac_change = $current->{mac} ne $vf->{mac};
    if ($mac_change) {
        run_command(['/sbin/ip', 'link', 'set', 'dev', $name, 'vf', $vf->{index}, 'mac', $vf->{mac}]);
    }
    my $bound = $current->{driver};
    if (($bound // '') ne $driver || $refresh_mac || ($mac_change && $driver ne 'vfio-pci')) {
        write_attribute("$path/driver_override", "$driver\n");
        write_attribute("$path/driver/unbind", $current->{pci}) if defined($bound);
        write_attribute("$pci_root/drivers_probe", $current->{pci});
        wait_until("$current->{pci} to bind to $driver", sub {
            return (driver_name($path) // '') eq $driver;
        });
    }
    return if $driver eq 'vfio-pci';
    run_command(['/usr/bin/udevadm', 'settle', '--timeout=10']);
    my @devs;
    wait_until("the network interface for $current->{pci}", sub {
        @devs = entries("$path/net") if -d "$path/net";
        return @devs == 1;
    });
    return if !defined($vf->{ifname});
    my $old = port_name($devs[0]);
    return if $old eq $vf->{ifname};
    run_command(['/sbin/ip', 'link', 'set', 'dev', $old, 'name', $vf->{ifname}]);
}

sub differs {
    my ($current, $vf, $host_name) = @_;
    return $current->{mac} ne $vf->{mac}
        || ($current->{driver} // '') ne $vf->{driver}
        || (defined($vf->{ifname}) && ($host_name // '') ne $vf->{ifname});
}

sub apply_port {
    my ($name, $before, $owners, $request, $guests, $netns) = @_;
    my $pf = pf_device($name);
    my %requested = map { $_->{index} => $_ } $request->{vfs}->@*;
    my %old = map { $_->{index} => $_ } @{ $before->{desired}->{vfs} // [] };
    my $resize = $request->{numvfs} != $before->{numvfs};
    for my $vf ($before->{vfs}->@*) {
        my $owner = $owners->{$vf->{pci}};
        my $unlocated = defined($vf->{driver}) && $vf->{driver} ne 'vfio-pci' && !defined($vf->{ifname});
        next if !defined($owner) && !$unlocated;
        my $index = $vf->{index};
        my $wanted = $requested{$index};
        my $old = $old{$index};
        my $change = $resize || (defined($old) && (!defined($wanted) || $json->encode($old) ne $json->encode($wanted)));
        if (defined($wanted)) {
            my $host_name = defined($old) ? $old->{ifname} : $vf->{ifname};
            $change ||= differs($vf, $wanted, $host_name);
        }
        my $reason = $owner // 'an unidentified network namespace';
        die "VF $index ($vf->{pci}) on $name is in use by $reason.\n" if $change;
    }

    if ($resize) {
        write_attribute("$pf/sriov_numvfs", '0') if $before->{numvfs};
        write_attribute("$pf/sriov_numvfs", "$request->{numvfs}") if $request->{numvfs};
        wait_until("$request->{numvfs} VFs on $name", sub {
            return 0 if number("$pf/sriov_numvfs") != $request->{numvfs};
            return !grep { !-l "$pf/virtfn$_" } 0 .. $request->{numvfs} - 1;
        });
        run_command(['/usr/bin/udevadm', 'settle', '--timeout=10']);
    }
    my ($state) = $resize ? observe($name, undef, $guests) : ($before);
    for my $vf ($request->{vfs}->@*) {
        my $current = $state->{vfs}->[$vf->{index}];
        next if defined($owners->{$current->{pci}});
        my $refresh_mac = $vf->{driver} ne 'vfio-pci' && ($current->{driver} // '') eq $vf->{driver}
            && $current->{mac} eq $vf->{mac} && permanent_mac($current, $netns) ne $vf->{mac};
        next if !$refresh_mac && !differs($current, $vf, $current->{ifname});
        change_vf($name, $current, $vf, $refresh_mac);
    }
    my ($after, undef, $after_netns) = observe($name, $request, $guests);
    die "Adapter $name reports $after->{numvfs} VFs after requesting $request->{numvfs}.\n"
        if $after->{numvfs} != $request->{numvfs};
    for my $vf ($request->{vfs}->@*) {
        my $current = $after->{vfs}->[$vf->{index}];
        my $host_name = $current->{ifname};
        $host_name = $old{$vf->{index}}->{ifname} if defined($owners->{$current->{pci}}) && $old{$vf->{index}};
        die "VF $vf->{index} on $name does not match the declaration after apply.\n"
            if differs($current, $vf, $host_name);
        if ($vf->{driver} ne 'vfio-pci') {
            wait_until("$current->{ifname} on $current->{pci} to report permanent MAC $vf->{mac}", sub {
                return permanent_mac($current, $after_netns) eq $vf->{mac};
            });
        }
    }
    return $after;
}

sub locked {
    my ($operation) = @_;
    my $result = lock_file($lock, 60, $operation);
    die $@ if $@;
    return $result;
}

sub get_port {
    my ($input) = @_;
    my $name = port_name($input);
    return locked(sub {
        pf_device($name);
        my ($state) = observe($name, saved($name), local_guests());
        return $state;
    });
}

sub update_port {
    my ($name, $request, $action) = @_;
    my $pf = pf_device($name);
    my $old = saved($name);
    return undef if $action eq 'delete' && !defined($old);
    $request = $old if $action eq 'restore';
    my $desired = normalize($name, $request, number("$pf/sriov_totalvfs"));
    my $guests = local_guests();
    my @ids = sort { $a <=> $b } keys %$guests;
    return with_guest_locks($guests, \@ids, sub {
        my $current_guests = local_guests();
        die "Local guest inventory changed during SR-IOV locking. Retry the request.\n"
            if $json->encode($guests) ne $json->encode($current_guests);
        if ($action eq 'set') {
            for my $path (qw(
                /etc/systemd/system/pve-overlay-sriov.service
                /etc/systemd/system/pve-guests.service.d/50-pve-overlay-sriov.conf
                /etc/systemd/system/pve-ha-lrm.service.d/50-pve-overlay-sriov.conf
                /usr/share/pve-overlay/sriov-restore
            )) {
                die "Install the SR-IOV boot file $path before saving declarations.\n" if !-f $path;
            }
        }
        my ($before, $owners, $netns) = observe($name, $old, $guests);
        my $after = eval {
            my $result = apply_port($name, $before, $owners, $desired, $guests, $netns);
            if ($action eq 'delete') {
                unlink("$state_dir/$name.json") or die "Cannot delete $state_dir/$name.json: $!\n";
            } elsif ($action eq 'set') {
                make_path($state_dir, { mode => 0755 });
                PVE::File::file_set_contents("$state_dir/$name.json", $json->encode($desired) . "\n", 0644);
            }
            $result;
        };
        if (my $error = $@) {
            my $actual = eval { my ($state) = observe($name, $old, $guests); $state };
            my $detail = $@ || $json->encode({ numvfs => $actual->{numvfs}, vfs => $actual->{vfs} });
            die "Cannot $action SR-IOV on $name: $error" . "Current VF state: $detail\n";
        }
        return $after;
    });
}

sub set_port {
    my ($input, $request) = @_;
    my $name = port_name($input);
    return locked(sub { update_port($name, $request, 'set') });
}

sub delete_port {
    my ($input) = @_;
    my $name = port_name($input);
    locked(sub { update_port($name, { numvfs => 0, vfs => [] }, 'delete') });
    return;
}

sub restore {
    locked(sub {
        return if !-d $state_dir;
        for my $entry (entries($state_dir)) {
            next if $entry !~ /\.json\z/;
            my ($name) = $entry =~ /\A($name_pattern)\.json\z/;
            die "Invalid SR-IOV declaration filename '$entry'.\n" if !defined($name);
            wait_until("physical interface $name", sub { -e "/sys/class/net/$name/device/sriov_numvfs" });
            update_port($name, undef, 'restore');
        }
    });
}

1;
