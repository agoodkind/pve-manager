package PVE::API2::KernelModules;

use strict;
use warnings;

use PVE::File;
use PVE::JSONSchema qw(get_standard_option);
use PVE::Tools qw(run_command);

use base qw(PVE::RESTHandler);

use vars qw($LOAD_FILE $ALLOW_FILE $SYS_MODULE_DIR $MODINFO_COMMAND $MODPROBE_COMMAND);

$LOAD_FILE = '/etc/modules-load.d/pve-overlay.conf';
$ALLOW_FILE = '/etc/pve-overlay/kernel-modules.allow';
$SYS_MODULE_DIR = '/sys/module';
$MODINFO_COMMAND = '/sbin/modinfo';
$MODPROBE_COMMAND = '/sbin/modprobe';

my $LOAD_FILE_MODE = 0644;
my $BUILTIN_MARKER = '(builtin)';

my $read_names = sub {
    my ($path) = @_;

    return [] if !-e $path;

    my $names = [];
    for my $line (split(/\n/, PVE::File::file_get_contents($path))) {
        $line =~ s/^\s+|\s+$//g;
        push @$names, $line if $line ne '';
    }
    return $names;
};

my $read_state = sub {
    my $modules = $read_names->($LOAD_FILE);

    my $loaded = {};
    for my $name (@$modules) {
        $loaded->{$name} = -d "$SYS_MODULE_DIR/$name" ? 1 : 0;
    }

    return { modules => $modules, loaded => $loaded };
};

my $modinfo_path = sub {
    my ($name) = @_;

    my $output = '';
    eval {
        run_command(
            [$MODINFO_COMMAND, '-n', '--', $name],
            outfunc => sub { $output .= shift() . "\n" },
            errfunc => sub { },
        );
    };
    return undef if $@;

    $output =~ s/^\s+|\s+$//g;
    return $output;
};

my $validate_name = sub {
    my ($name, $allowed) = @_;

    die "kernel module '$name': the name does not match ^[a-z0-9_]+\$\n"
        if $name !~ /^([a-z0-9_]+)\z/;
    my $untainted = $1;

    die "kernel module '$untainted': the name is not in $ALLOW_FILE\n"
        if !$allowed->{$untainted};

    my $path = $modinfo_path->($untainted);
    die "kernel module '$untainted': modinfo -n fails for the running kernel\n"
        if !defined($path) || $path eq '';
    die "kernel module '$untainted': the module is built into the running kernel\n"
        if $path eq $BUILTIN_MARKER;

    return $untainted;
};

my $state_returns = {
    type => 'object',
    properties => {
        modules => {
            type => 'array',
            description => 'The module names in the persistent list, in file order.',
            items => { type => 'string' },
        },
        loaded => {
            type => 'object',
            description => 'One entry per listed module: 1 when the module is loaded.',
            additionalProperties => { type => 'integer', minimum => 0, maximum => 1 },
        },
    },
};

__PACKAGE__->register_method({
    name => 'get_kernel_modules',
    path => '',
    method => 'GET',
    description => "Get the persistent kernel module list of a node.",
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.KernelModules.Audit']],
    },
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
        },
    },
    returns => $state_returns,
    code => sub {
        return $read_state->();
    },
});

__PACKAGE__->register_method({
    name => 'set_kernel_modules',
    path => '',
    method => 'PUT',
    description => "Set the persistent kernel module list of a node and load the modules.",
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.KernelModules.Modify']],
    },
    protected => 1,
    proxyto => 'node',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            modules => {
                type => 'array',
                description => 'The module names for the persistent list.',
                items => { type => 'string' },
            },
        },
    },
    returns => $state_returns,
    code => sub {
        my ($param) = @_;

        my $allowed = { map { $_ => 1 } @{ $read_names->($ALLOW_FILE) } };

        my $names = [];
        my $seen = {};
        for my $requested (@{ $param->{modules} }) {
            my $name = $validate_name->($requested, $allowed);
            next if $seen->{$name}++;
            push @$names, $name;
        }

        my $content = '';
        for my $name (@$names) {
            $content .= "$name\n";
        }
        PVE::File::file_set_contents($LOAD_FILE, $content, $LOAD_FILE_MODE);

        for my $name (@$names) {
            run_command([$MODPROBE_COMMAND, '--', $name]);
        }

        return $read_state->();
    },
});

1;
