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
        next if $line eq '' || $line =~ /^[#;]/;
        push @$names, $line;
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
    my $errors = '';
    eval {
        run_command(
            [$MODINFO_COMMAND, '-n', '--', $name],
            outfunc => sub { $output .= shift() . "\n" },
            errfunc => sub { $errors .= shift() . "\n" },
        );
    };
    my $failed = $@ ? 1 : 0;

    $errors =~ s/^\s+|\s+$//g;
    return (undef, $errors) if $failed;

    $output =~ s/^\s+|\s+$//g;
    return ($output, $errors);
};

my $validate_name = sub {
    my ($name, $allowed) = @_;

    die "Kernel module '$name' does not match the required pattern ^[a-z0-9_]+\$.\n"
        if $name !~ /^([a-z0-9_]+)\z/;
    my $untainted = $1;

    die "Kernel module '$untainted' is not in $ALLOW_FILE.\n"
        if !$allowed->{$untainted};

    my ($path, $errors) = $modinfo_path->($untainted);
    if (!defined($path) || $path eq '') {
        my $message = "The validator rejects kernel module '$untainted' because modinfo -n fails or returns no path for the running kernel.";
        $message .= " The modinfo command wrote to stderr: $errors" if $errors ne '';
        die "$message\n";
    }
    die "Kernel module '$untainted' is built into the running kernel.\n"
        if $path eq $BUILTIN_MARKER;

    return $untainted;
};

my $state_returns = {
    type => 'object',
    properties => {
        modules => {
            type => 'array',
            description => 'The response lists persistent module names in file order.',
            items => { type => 'string' },
        },
        loaded => {
            type => 'object',
            description => 'The response reports whether each listed module is loaded (1) or is not loaded (0).',
            additionalProperties => { type => 'integer', minimum => 0, maximum => 1 },
        },
    },
};

__PACKAGE__->register_method({
    name => 'get_kernel_modules',
    path => '',
    method => 'GET',
    description => "GET returns the persistent kernel module list and a loaded flag for each module on the node.",
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
    description => "PUT replaces the persistent kernel module list and loads accepted modules on the node. PUT never unloads modules.",
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
                description => 'The request supplies module names to replace the persistent list.',
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

        for my $name (@$names) {
            my $errors = '';
            eval {
                run_command(
                    [$MODPROBE_COMMAND, '--', $name],
                    errfunc => sub { $errors .= shift() . "\n" },
                );
            };
            if ($@) {
                my $failure = $@;
                $errors =~ s/^\s+|\s+$//g;
                $failure =~ s/^\s+|\s+$//g;
                my $detail = $errors;
                $detail = $failure if $detail eq '';
                die "The modprobe command failed for kernel module '$name': $detail\n";
            }
        }

        my $content = '';
        for my $name (@$names) {
            $content .= "$name\n";
        }
        PVE::File::file_set_contents($LOAD_FILE, $content, $LOAD_FILE_MODE);

        return $read_state->();
    },
});

1;
