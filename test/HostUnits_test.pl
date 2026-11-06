#!/usr/bin/perl -T

# The test reads and controls units that a target policy lists through the REST methods and
# checks real units. It needs systemd as process 1, writes below /etc/pve-overlay,
# /etc/systemd/system, /var/lib/pve-overlay, /run/systemd/system, and /srv, and must run as
# root in a disposable container with the overlay access control patch applied.

use strict;
use warnings;

use lib qw(.. .);

use File::Path qw(make_path remove_tree);

use PVE::HostArtifacts;
use PVE::RPCEnvironment;

use HostArtifactsTest;

delete @ENV{qw(PATH IFS CDPATH ENV BASH_ENV)};

HostArtifactsTest::require_disposable_root();
die "this test needs systemd as process 1\n" if !-d '/run/systemd/system';

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'host-artifacts-test.cfg');

my $ROOT = '/srv/host-units-test';
my $STATE_DIR = '/var/lib/pve-overlay/host-artifacts';
my $UNIT_DIR = '/etc/systemd/system';
my $RUNTIME_UNIT_DIR = '/run/systemd/system';
my $SYSTEMCTL = '/usr/bin/systemctl';
my $MODIFY_TOKEN = 'deploy@pve!install';
my $UNIT = 'hostunit-test.service';
my $FAILING_UNIT = 'hostunit-failing.service';
my $OTHER_UNIT = 'hostunit-other.service';
my $UNLISTED_UNIT = 'hostunit-unlisted.service';
my $UNRELATED_UNIT = 'hostunit-unrelated.service';
my $INTERRUPTED_UNIT = 'hostunit-interrupted.service';

my $check = \&HostArtifactsTest::check;
my $check_match = \&HostArtifactsTest::check_match;
my $json = HostArtifactsTest::json();

sub run_systemctl {
    my (@arguments) = @_;

    system({$SYSTEMCTL} $SYSTEMCTL, @arguments) == 0
        or die "systemctl @arguments failed with exit code " . ($? >> 8) . "\n";
}

sub unit_property {
    my ($unit, $property) = @_;

    open(my $handle, '-|', $SYSTEMCTL, 'show', "--property=$property", '--value', $unit)
        or die "cannot run systemctl show: $!\n";
    my $value = <$handle> // '';
    close($handle);
    chomp($value);
    return $value;
}

sub unit_content {
    my ($exec_start) = @_;

    return "[Unit]\nStartLimitIntervalSec=0\n\n"
        . "[Service]\nType=oneshot\nRemainAfterExit=yes\nExecStart=$exec_start\n\n"
        . "[Install]\nWantedBy=multi-user.target\n";
}

sub unit_path {
    my ($unit) = @_;

    return "$UNIT_DIR/$unit";
}

sub unit_entry {
    my ($unit) = @_;

    return { path => unit_path($unit), mode => '0644', owner => 'root', group => 'root' };
}

# The function installs files for a target with the module entry point.
sub install_files {
    my ($document, $files, $name) = @_;

    my $policy = PVE::HostArtifacts::load_policy(HostArtifactsTest::write_policy($document));
    my $archive = "$ROOT/$name.tar.gz";
    my ($manifest, $members) = HostArtifactsTest::artifact(
        $document, { map { $_ => { content => $files->{$_} } } keys %$files },
    );
    HostArtifactsTest::write_archive(
        $archive, [{ name => 'manifest.json', content => $json->encode($manifest) }, @$members],
    );
    PVE::HostArtifacts::with_target_lock(
        $policy->{target},
        sub {
            PVE::HostArtifacts::install_verified_archive(
                $policy, HostArtifactsTest::request($archive), $archive, "UPID:test:$name",
                $MODIFY_TOKEN,
            );
        },
    );
    return $policy->{target};
}

sub unit_get {
    my ($user, $target, $unit) = @_;

    return HostArtifactsTest::api_request($rpcenv, $user, 'GET', "$target/units/$unit", {});
}

sub unit_post {
    my ($user, $target, $unit, $params) = @_;

    return HostArtifactsTest::api_request(
        $rpcenv, $user, 'POST', "$target/units/$unit", $params,
    );
}

# The function starts a unit action and returns the task status and the task log.
sub unit_action {
    my ($target, $unit, $action) = @_;

    my $response = unit_post($MODIFY_TOKEN, $target, $unit, { action => $action });
    die "the $action request returned status $response->{status}: "
        . ($response->{message} // '') . "\n"
        if $response->{status} != 200;
    return HostArtifactsTest::wait_for_task($response->{data});
}

sub unit_state {
    my ($target, $unit) = @_;

    my $response = unit_get($MODIFY_TOKEN, $target, $unit);
    die "GET returned status $response->{status}: " . ($response->{message} // '') . "\n"
        if $response->{status} != 200;
    return $response->{data};
}

sub expect_state {
    my ($label, $target, $unit, $file_state, $active_state) = @_;

    my $state = unit_state($target, $unit);
    $check->(
        "GET reports $file_state and $active_state $label",
        $state->{found}
            && $state->{unit_file_state} eq $file_state
            && $state->{active_state} eq $active_state,
        $json->encode($state),
    );
}

remove_tree($ROOT);
make_path("$ROOT/etc", "$ROOT/other", "$ROOT/interrupted", { mode => 0755 });
for my $unit ($UNIT, $FAILING_UNIT, $OTHER_UNIT, $UNLISTED_UNIT, $INTERRUPTED_UNIT) {
    system({$SYSTEMCTL} $SYSTEMCTL, 'disable', '--quiet', $unit);
    unlink(unit_path($unit));
}

my $app_file = "$ROOT/etc/app.conf";
my $document = HostArtifactsTest::base_policy(
    'suburban/unit-test',
    [
        { path => $app_file, mode => '0644', owner => 'root', group => 'root' },
        unit_entry($UNIT),
        unit_entry($FAILING_UNIT),
    ],
);
my $target = HostArtifactsTest::write_policy($document);
my $other_document = HostArtifactsTest::base_policy(
    'suburban/unit-other',
    [
        { path => "$ROOT/other/app.conf", mode => '0644', owner => 'root', group => 'root' },
        unit_entry($OTHER_UNIT),
    ],
);
my $other_target = HostArtifactsTest::write_policy($other_document);
remove_tree("$STATE_DIR/$target", "$STATE_DIR/$other_target");

HostArtifactsTest::write_file("$RUNTIME_UNIT_DIR/$UNRELATED_UNIT", unit_content('/bin/true'));
HostArtifactsTest::write_file(unit_path($UNLISTED_UNIT), unit_content('/bin/true'));
run_systemctl('daemon-reload');
run_systemctl('restart', $UNRELATED_UNIT);

# The tests check the target before it has an installed record.

my $missing = unit_state($target, $UNIT);
$check->(
    'GET reports found 0 for a listed unit without a unit file',
    !$missing->{found} && $missing->{name} eq $UNIT && !exists($missing->{unit_file_state}),
    $json->encode($missing),
);
my $uninstalled = unit_post($MODIFY_TOKEN, $target, $UNIT, { action => 'daemon-reload' });
$check_match->(
    'a unit action without an installed record fails',
    $uninstalled->{message},
    qr/does not have an installed record/,
);

install_files(
    $other_document,
    { "$ROOT/other/app.conf" => "other\n", unit_path($OTHER_UNIT) => unit_content('/bin/true') },
    'other',
);
run_systemctl('daemon-reload');
run_systemctl('start', $OTHER_UNIT);
my $unit_content = unit_content('/bin/true');
install_files(
    $document,
    {
        $app_file => "app\n",
        unit_path($UNIT) => $unit_content,
        unit_path($FAILING_UNIT) => unit_content('/bin/false'),
    },
    'app',
);
my ($interrupted_target, $interrupted_paths) = HostArtifactsTest::interrupted_target(
    'suburban/unit-interrupted',
    "$ROOT/interrupted",
    { unit_path($INTERRUPTED_UNIT) => unit_content('/bin/true') },
);

# The function returns the state that every unit request leaves unchanged.
sub unrelated_state {
    return $json->encode({
        target => HostArtifactsTest::target_state($target, $app_file),
        other_target => HostArtifactsTest::target_state(
            $other_target, "$ROOT/other/app.conf", unit_path($OTHER_UNIT),
        ),
        interrupted_target => HostArtifactsTest::target_state(
            $interrupted_target, unit_path($INTERRUPTED_UNIT), @$interrupted_paths,
        ),
        other_unit => unit_property($OTHER_UNIT, 'InvocationID'),
        unrelated_unit => unit_property($UNRELATED_UNIT, 'InvocationID'),
    });
}
my $unrelated_before = unrelated_state();
my $check_unrelated = sub {
    my ($label) = @_;

    $check->(
        'the files, records, journals, and lock files of the targets and the InvocationID'
            . " values of the other units stay unchanged after $label",
        unrelated_state() eq $unrelated_before,
    );
};

# The function returns the state of the test unit that a rejected request leaves unchanged.
sub test_unit_state {
    return join(
        ' ',
        HostArtifactsTest::target_state($target, unit_path($UNIT)),
        unit_property($UNIT, 'InvocationID'),
        unit_property($UNIT, 'ActiveState'),
        unit_property($UNIT, 'UnitFileState'),
    );
}

# The tests check callers without the required privileges.

for my $user ('deploy@pve!audit', 'deploy@pve!rotate', 'deploy@pve!none') {
    my $response = unit_post($user, $target, $UNIT, { action => 'start' });
    $check->("$user cannot run a unit action", $response->{status} == 403);
}
my $no_audit = unit_get('deploy@pve!none', $target, $UNIT);
$check->('a token without Sys.HostArtifacts.Audit cannot read a unit', $no_audit->{status} == 403);
my $audit = unit_get('deploy@pve!audit', $target, $UNIT);
$check->('an audit-only token can read a unit', $audit->{status} == 200);
$check->(
    'the denied requests do not start the unit',
    unit_property($UNIT, 'ActiveState') eq 'inactive',
);
$check_unrelated->('the denied requests');

# The tests check the actions on an owned unit.

my ($status) = unit_action($target, $UNIT, 'daemon-reload');
$check->('daemon-reload succeeds', $status eq 'OK', $status);
expect_state('after daemon-reload', $target, $UNIT, 'disabled', 'inactive');

($status) = unit_action($target, $UNIT, 'enable');
$check->('enable succeeds', $status eq 'OK', $status);
expect_state('after enable', $target, $UNIT, 'enabled', 'inactive');

($status) = unit_action($target, $UNIT, 'start');
$check->('start succeeds', $status eq 'OK', $status);
expect_state('after start', $target, $UNIT, 'enabled', 'active');
my $invocation = unit_property($UNIT, 'InvocationID');

my $before_get = test_unit_state();
unit_state($target, $UNIT);
unit_get('deploy@pve!audit', $target, $UNIT);
$check->('GET does not change the unit or the target files', test_unit_state() eq $before_get);

($status) = unit_action($target, $UNIT, 'restart');
$check->('restart succeeds', $status eq 'OK', $status);
my $restarted = unit_property($UNIT, 'InvocationID');
$check->('restart starts a new invocation', $restarted ne $invocation && $restarted ne '');

($status) = unit_action($target, $UNIT, 'reenable');
$check->('reenable succeeds', $status eq 'OK', $status);
expect_state('after reenable', $target, $UNIT, 'enabled', 'active');
$check->(
    'reenable does not restart the unit',
    unit_property($UNIT, 'InvocationID') eq $restarted,
);

($status) = unit_action($target, $UNIT, 'start');
$check->('a repeated start succeeds', $status eq 'OK', $status);
$check->(
    'a repeated start does not restart an active unit',
    unit_property($UNIT, 'InvocationID') eq $restarted,
);
$check_unrelated->('the owned unit actions');

# The tests check rejected requests.

my $unlisted = qr/does not list the unit file/;
my $start = { action => 'start' };
my $rejections = [
    ['a unit of another target', $OTHER_UNIT, $start, $unlisted],
    ['a unit that a policy does not list', $UNLISTED_UNIT, $start, $unlisted],
    ['a unit that is not a service', 'hostunit-test.socket', $start, undef],
    ['an unsupported action', $UNIT, { action => 'mask' }, undef],
    ['extra arguments', $UNIT, { action => 'start', arguments => '--force' }, undef],
    ['a request without an action', $UNIT, {}, undef],
];
for my $rejection (@$rejections) {
    my ($label, $unit, $params, $pattern) = @$rejection;
    my $before = test_unit_state();
    my $response = unit_post($MODIFY_TOKEN, $target, $unit, $params);
    $check->("$label fails", $response->{status} != 200, $response->{status});
    $check_match->("$label reports the reason", $response->{message}, $pattern) if $pattern;
    $check->("$label leaves the test unit unchanged", test_unit_state() eq $before);
}
my $other_get = unit_get($MODIFY_TOKEN, $target, $OTHER_UNIT);
$check_match->(
    'GET fails for a unit of another target',
    $other_get->{message},
    qr/does not list the unit file/,
);
HostArtifactsTest::check_error(
    'the module rejects an unsupported action',
    sub { PVE::HostArtifacts::check_unit_request($target, $UNIT, 'mask') },
    qr/the unit action 'mask' is not supported/,
);
$check->(
    'the rejected requests do not change the unlisted unit',
    unit_property($UNLISTED_UNIT, 'ActiveState') eq 'inactive',
);
$check_unrelated->('the rejected requests');

# The tests check changed unit files.

my $path = unit_path($UNIT);
for my $change (
    ['content', sub { HostArtifactsTest::write_file($path, "$unit_content# changed\n") }],
    ['mode', sub { chmod(0600, $path) or die "cannot change $path: $!\n" }],
    ['owner', sub { chown(1, 1, $path) or die "cannot change $path: $!\n" }],
) {
    my ($kind, $code) = @$change;
    $code->();
    my $before = test_unit_state();
    my $response = unit_post($MODIFY_TOKEN, $target, $UNIT, { action => 'restart' });
    $check_match->(
        "a unit file with another $kind fails",
        $response->{message},
        qr/does not match the installed record/,
    );
    $check->("the rejected $kind change leaves the unit unchanged", test_unit_state() eq $before);
    HostArtifactsTest::write_file($path, $unit_content);
    chown(0, 0, $path) or die "cannot change $path: $!\n";
}
($status) = unit_action($target, $UNIT, 'daemon-reload');
$check->('a restored unit file permits actions again', $status eq 'OK', $status);
$check_unrelated->('the changed unit files');

# The tests check an interrupted installation.

my $interrupted_before = unrelated_state();
my $interrupted =
    unit_post($MODIFY_TOKEN, $interrupted_target, $INTERRUPTED_UNIT, { action => 'start' });
$check_match->(
    'a unit action fails while the target has an interrupted installation',
    $interrupted->{message},
    qr/interrupted installation/,
);
$check->(
    'the rejected action does not start the unit',
    unit_property($INTERRUPTED_UNIT, 'ActiveState') ne 'active',
);
$check->(
    'the rejected action leaves the interrupted target unchanged',
    unrelated_state() eq $interrupted_before,
);

# The tests check a failed action.

($status) = unit_action($target, $FAILING_UNIT, 'daemon-reload');
my ($failed_status, $failed_log) = unit_action($target, $FAILING_UNIT, 'start');
$check_match->(
    'a failed start reports the systemctl failure in the task status',
    $failed_status,
    qr/systemctl start -- \Q$FAILING_UNIT\E failed/,
);
$check_match->(
    'the task log contains the systemctl failure',
    $failed_log,
    qr/systemctl start -- \Q$FAILING_UNIT\E failed/,
);
expect_state('after the failed start', $target, $FAILING_UNIT, 'disabled', 'failed');
$check_unrelated->('the failed action');

# The tests check stop and disable.

($status) = unit_action($target, $UNIT, 'stop');
$check->('stop succeeds', $status eq 'OK', $status);
($status) = unit_action($target, $UNIT, 'disable');
$check->('disable succeeds', $status eq 'OK', $status);
expect_state('after stop and disable', $target, $UNIT, 'disabled', 'inactive');
$check_unrelated->('stop and disable');

# The tests check the cleanup.

PVE::HostArtifacts::with_target_lock(
    $interrupted_target, sub { PVE::HostArtifacts::recover($interrupted_target) },
);
run_systemctl('stop', $OTHER_UNIT, $UNRELATED_UNIT);
system({$SYSTEMCTL} $SYSTEMCTL, 'reset-failed', $FAILING_UNIT);
for my $unit ($UNIT, $FAILING_UNIT, $OTHER_UNIT, $UNLISTED_UNIT, $INTERRUPTED_UNIT) {
    unlink(unit_path($unit));
}
unlink("$RUNTIME_UNIT_DIR/$UNRELATED_UNIT")
    or die "cannot delete $RUNTIME_UNIT_DIR/$UNRELATED_UNIT: $!\n";
run_systemctl('daemon-reload');
$check->(
    'the cleanup removes the test units',
    unit_property($UNIT, 'LoadState') eq 'not-found'
        && unit_property($UNRELATED_UNIT, 'LoadState') eq 'not-found',
);
remove_tree($ROOT, "$STATE_DIR/$target", "$STATE_DIR/$other_target");
$check->('the cleanup removes the test files', !-e $ROOT);

print "all tests passed\n";

exit(0);
