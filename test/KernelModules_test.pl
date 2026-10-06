#!/usr/bin/perl

use strict;
use warnings;

use lib ('.', '..');

use File::Temp qw(tempdir);
use Test::More;

use PVE::API2::KernelModules;

my $root = tempdir(CLEANUP => 1);
mkdir "$root/sys" or die "cannot create $root/sys: $!\n";
mkdir "$root/sys/loaded_mod" or die "cannot create $root/sys/loaded_mod: $!\n";

my $modinfo_script = <<'SCRIPT';
#!/bin/sh
name="$3"
case "$name" in
    builtin_mod) echo "(builtin)" ;;
    missing_mod) echo "modinfo: ERROR: Module $name not found." >&2; exit 1 ;;
    *) echo "/lib/modules/test/$name.ko" ;;
esac
SCRIPT

my $modprobe_script = <<"SCRIPT";
#!/bin/sh
echo "\$2" >> "$root/modprobe.log"
if [ "\$2" = "fail_mod" ]; then
    echo "modprobe: FATAL: Module fail_mod cannot be inserted." >&2
    exit 1
fi
SCRIPT

sub write_file {
    my ($path, $content, $mode) = @_;
    open(my $handle, '>', $path) or die "cannot write $path: $!\n";
    print {$handle} $content;
    close($handle) or die "cannot write $path: $!\n";
    chmod($mode, $path) or die "cannot chmod $path: $!\n";
}

write_file("$root/modinfo", $modinfo_script, 0755);
write_file("$root/modprobe", $modprobe_script, 0755);
write_file(
    "$root/allow",
    "loaded_mod\nunloaded_mod\nbuiltin_mod\nmissing_mod\nsecond_mod\nfail_mod\n",
    0644,
);

$PVE::API2::KernelModules::LOAD_FILE = "$root/pve-overlay.conf";
$PVE::API2::KernelModules::ALLOW_FILE = "$root/allow";
$PVE::API2::KernelModules::SYS_MODULE_DIR = "$root/sys";
$PVE::API2::KernelModules::MODINFO_COMMAND = "$root/modinfo";
$PVE::API2::KernelModules::MODPROBE_COMMAND = "$root/modprobe";

sub read_file {
    my ($path) = @_;
    return '' if !-e $path;
    open(my $handle, '<', $path) or die "cannot read $path: $!\n";
    local $/ = undef;
    my $content = <$handle>;
    close($handle);
    return $content;
}

sub put_modules {
    my ($modules) = @_;
    return PVE::API2::KernelModules->set_kernel_modules({
        node => 'localhost',
        modules => $modules,
    });
}

sub assert_rejected {
    my ($modules, $pattern, $label) = @_;
    my $before = read_file($PVE::API2::KernelModules::LOAD_FILE);
    unlink("$root/modprobe.log");

    my $result = eval { put_modules($modules) };
    like($@, $pattern, "$label: error message");
    is(read_file($PVE::API2::KernelModules::LOAD_FILE), $before, "$label: file unchanged");
    ok(!-e "$root/modprobe.log", "$label: modprobe not run");
}

my $initial = PVE::API2::KernelModules->get_kernel_modules({ node => 'localhost' });
is_deeply($initial, { modules => [], loaded => {} }, 'a missing load file lists no modules');

assert_rejected(['Bad-Name'], qr/'Bad-Name'.*does not match/, 'malformed name');
assert_rejected(['loaded_mod', 'bad name'], qr/'bad name'.*does not match/, 'name with space');
assert_rejected(['not_allowed'], qr/'not_allowed'.*not in /, 'name outside the allowlist');
assert_rejected(
    ['loaded_mod', 'builtin_mod'],
    qr/'builtin_mod'.*built into the running kernel/,
    'builtin module',
);
assert_rejected(['missing_mod'], qr/'missing_mod'.*modinfo -n fails/, 'module without modinfo');
assert_rejected(
    ['missing_mod'],
    qr/modinfo: ERROR: Module missing_mod not found\./,
    'modinfo failure includes its stderr',
);

my $state = put_modules(['loaded_mod', 'unloaded_mod', 'loaded_mod']);
is(
    read_file($PVE::API2::KernelModules::LOAD_FILE),
    "loaded_mod\nunloaded_mod\n",
    'the load file lists each name once, one per line',
);
is(read_file("$root/modprobe.log"), "loaded_mod\nunloaded_mod\n", 'modprobe runs for each name');
is_deeply(
    $state,
    {
        modules => ['loaded_mod', 'unloaded_mod'],
        loaded => { loaded_mod => 1, unloaded_mod => 0 },
    },
    'PUT returns the module list and the loaded flags',
);
is_deeply(
    PVE::API2::KernelModules->get_kernel_modules({ node => 'localhost' }),
    $state,
    'GET returns the state that PUT wrote',
);

$state = put_modules(['second_mod']);
is(read_file($PVE::API2::KernelModules::LOAD_FILE), "second_mod\n", 'PUT replaces the list');

my $before_failure = read_file($PVE::API2::KernelModules::LOAD_FILE);
unlink("$root/modprobe.log");
eval { put_modules(['loaded_mod', 'fail_mod']) };
like($@, qr/fail_mod/, 'a modprobe failure error includes the module name');
like(
    $@,
    qr/modprobe: FATAL: Module fail_mod cannot be inserted\./,
    'a modprobe failure error includes the modprobe stderr',
);
is(
    read_file($PVE::API2::KernelModules::LOAD_FILE),
    $before_failure,
    'a modprobe failure keeps the load file unchanged',
);
is(
    read_file("$root/modprobe.log"),
    "loaded_mod\nfail_mod\n",
    'modprobe runs in request order until the failure',
);

$state = put_modules([]);
is(read_file($PVE::API2::KernelModules::LOAD_FILE), '', 'an empty list empties the load file');
is_deeply($state, { modules => [], loaded => {} }, 'PUT of an empty list returns no modules');

put_modules(['loaded_mod']);
for my $invalid ({ name => 'loaded_mod' }, undef) {
    eval { put_modules($invalid) };
    like($@, qr/modules/, 'the schema rejects a modules value that is not an array');
}
eval { PVE::API2::KernelModules->set_kernel_modules({ node => 'localhost' }) };
like($@, qr/modules/, 'the schema rejects a request without modules');
is(read_file($PVE::API2::KernelModules::LOAD_FILE), "loaded_mod\n", 'rejected shapes keep the file');

write_file(
    $PVE::API2::KernelModules::LOAD_FILE,
    "# managed by hand\nloaded_mod\n; disabled\n  # indented comment\nunloaded_mod\n\n",
    0644,
);
is_deeply(
    PVE::API2::KernelModules->get_kernel_modules({ node => 'localhost' }),
    {
        modules => ['loaded_mod', 'unloaded_mod'],
        loaded => { loaded_mod => 1, unloaded_mod => 0 },
    },
    'GET skips comment lines that start with # or ;',
);

write_file(
    $PVE::API2::KernelModules::ALLOW_FILE,
    "# allowed modules\nloaded_mod\n; more modules\nunloaded_mod\n",
    0644,
);
$state = put_modules(['loaded_mod', 'unloaded_mod']);
is_deeply(
    $state->{modules},
    ['loaded_mod', 'unloaded_mod'],
    'an allowlist with comment lines still accepts its module entries',
);
assert_rejected(['# allowed modules'], qr/'# allowed modules'/, 'allowlist comment text');
assert_rejected(['; more modules'], qr/'; more modules'/, 'allowlist semicolon comment text');

unlink($PVE::API2::KernelModules::ALLOW_FILE);
assert_rejected(['loaded_mod'], qr/'loaded_mod'.*not in /, 'a missing allowlist is empty');

done_testing();
