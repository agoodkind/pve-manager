#!/usr/bin/perl -T

# The test sets host secret fields through the REST method and checks the storage files, the
# secret records, and real consumer units. It needs systemd as process 1, writes below
# /etc/pve-overlay, /var/lib/pve-overlay, /run/systemd/system, and /srv, and must run as root
# in a disposable container with the overlay access control patch applied.

use strict;
use warnings;

use lib qw(.. .);

use Cwd qw(abs_path);
use Digest::SHA;
use File::Path qw(make_path remove_tree);
use POSIX qw();
use Time::HiRes qw();

use PVE::HostArtifacts;
use PVE::RPCEnvironment;

use HostArtifactsTest;

my $consumer_script = abs_path('host-secret-consumer.sh');
die "cannot find host-secret-consumer.sh\n"
    if !defined($consumer_script) || $consumer_script !~ m{\A(/[A-Za-z0-9._/-]+)\z};
$consumer_script = $1;
delete @ENV{qw(PATH IFS CDPATH ENV BASH_ENV)};

HostArtifactsTest::require_disposable_root();
die "this test needs systemd as process 1\n" if !-d '/run/systemd/system';

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'host-artifacts-test.cfg');

my $ROOT = '/srv/host-secrets-test';
my $STATE_DIR = '/var/lib/pve-overlay/host-artifacts';
my $UNIT_DIR = '/run/systemd/system';
my $SYSTEMCTL = '/usr/bin/systemctl';
my $JOURNALCTL = '/usr/bin/journalctl';
my $FIELD = 'TEST_API_KEY';
my $OTHER_FIELD = 'OTHER_API_KEY';
my $CONSUMER = 'hostsecret-consumer.service';
my $OTHER_CONSUMER = 'hostsecret-other.service';
my $UNRELATED = 'hostsecret-unrelated.service';
my $OTHER_POLICY_UNIT = 'hostsecret-other-policy.service';
my $SECRET_TOKEN = 'deploy@pve!rotate';
my $WAIT_SECONDS = 120;

my $check = \&HostArtifactsTest::check;
my $check_match = \&HostArtifactsTest::check_match;
my $json = HostArtifactsTest::json();

# Every test value contains the marker. The test checks that logs, responses, and records
# do not contain the marker, and the test does not print it.
my $MARKER = 'hsmark' . substr(Digest::SHA::sha256_hex(time() . $$), 0, 16);
my $secret_file = "$ROOT/secrets/secrets.env";
my $other_secret_file = "$ROOT/other/secrets.env";
my $artifact_file = "$ROOT/etc/app.conf";
my @upids;
my @messages;

sub value {
    my ($label) = @_;

    return "$MARKER-$label-value";
}

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

sub wait_for_state {
    my ($unit, $state) = @_;

    my $deadline = Time::HiRes::time() + $WAIT_SECONDS;
    while (unit_property($unit, 'ActiveState') ne $state) {
        die "$unit is not $state after $WAIT_SECONDS seconds\n"
            if Time::HiRes::time() > $deadline;
        Time::HiRes::sleep(0.1);
    }
}

sub write_unit {
    my ($unit, $environment_file, $exec_start) = @_;

    my $content = "[Unit]\nStartLimitIntervalSec=0\n\n";
    $content .= "[Service]\nType=oneshot\nRemainAfterExit=yes\n";
    $content .= "EnvironmentFile=-$environment_file\n" if defined($environment_file);
    $content .= "ExecStart=$exec_start\n";
    HostArtifactsTest::write_file("$UNIT_DIR/$unit", $content);
}

sub read_or_absent {
    my ($path) = @_;

    return -e $path ? HostArtifactsTest::read_file($path) : 'absent';
}

sub file_state {
    my ($path) = @_;

    my @stat = lstat($path);
    return 'absent' if !@stat;
    my $digest = Digest::SHA->new(256)->addfile($path)->hexdigest();
    return join(':', $digest, @stat[1, 2, 4, 5, 9]);
}

sub secret_request {
    my ($user, $target, $field, $value, $version) = @_;

    my $response = HostArtifactsTest::api_request(
        $rpcenv, $user, 'PUT', "$target/secrets/$field",
        { value => $value, version => $version },
    );
    push @messages, ($response->{message} // '') . $json->encode($response->{errors} // {});
    return $response;
}

# The function starts a secret task and returns its status line.
sub set_secret {
    my ($target, $field, $value, $version) = @_;

    my $response = secret_request($SECRET_TOKEN, $target, $field, $value, $version);
    die "the secret request returned status $response->{status}\n"
        if $response->{status} != 200;
    push @upids, $response->{data};
    my ($status) = HostArtifactsTest::wait_for_task($response->{data});
    return $status;
}

sub secret_state {
    my ($target, $field) = @_;

    my $response =
        HostArtifactsTest::api_request($rpcenv, $SECRET_TOKEN, 'GET', $target, {});
    die "GET returned status $response->{status}\n" if $response->{status} != 200;
    my ($state) = grep { $_->{field} eq $field } @{ $response->{data}->{secrets} };
    return $state;
}

sub secret_record {
    my ($target, $field) = @_;

    my $path = "$STATE_DIR/$target/secrets.json";
    return undef if !-e $path;
    return $json->decode(HostArtifactsTest::read_file($path))->{fields}->{$field};
}

sub content_sha {
    my ($field, $value) = @_;

    return Digest::SHA::sha256_hex("$field=$value\n");
}

sub received {
    return read_or_absent("$ROOT/state/received");
}

sub received_value {
    my ($label) = @_;

    return Digest::SHA::sha256_hex(value($label)) . "\n";
}

remove_tree($ROOT);
make_path(
    "$ROOT/secrets", "$ROOT/other", "$ROOT/etc", "$ROOT/state", "$ROOT/other-state",
    { mode => 0755 },
);

my $secret_descriptor = {
    name => $FIELD,
    storage_path => $secret_file,
    mode => '0600',
    owner => 'root',
    group => 'root',
    pattern => '[A-Za-z0-9-]+',
    min_length => 16,
    max_length => 128,
    consumer_units => [$CONSUMER],
};
my $document = HostArtifactsTest::base_policy(
    'suburban/secret-test',
    [{ path => $artifact_file, mode => '0644', owner => 'root', group => 'root' }],
);
$document->{secret_fields} = [$secret_descriptor];
my $target = HostArtifactsTest::write_policy($document);
my $policy = PVE::HostArtifacts::load_policy($target);

my $other_artifact_file = "$ROOT/other/app.conf";
my $other_document = HostArtifactsTest::base_policy(
    'suburban/secret-other',
    [{ path => $other_artifact_file, mode => '0644', owner => 'root', group => 'root' }],
);
$other_document->{secret_fields} = [{
    %$secret_descriptor,
    name => $OTHER_FIELD,
    storage_path => $other_secret_file,
    consumer_units => [$OTHER_CONSUMER],
}];
my $other_target = HostArtifactsTest::write_policy($other_document);
remove_tree("$STATE_DIR/$target", "$STATE_DIR/$other_target");

write_unit($CONSUMER, $secret_file, "/bin/bash $consumer_script $ROOT/state");
write_unit(
    $OTHER_CONSUMER, $other_secret_file, "/bin/bash $consumer_script $ROOT/other-state",
);
write_unit($UNRELATED, undef, '/bin/true');
run_systemctl('daemon-reload');
system({$SYSTEMCTL} $SYSTEMCTL, 'reset-failed', $CONSUMER, $OTHER_CONSUMER, $UNRELATED);
run_systemctl('restart', $CONSUMER, $OTHER_CONSUMER, $UNRELATED);

# The function installs one file for a target using the module entry point.
sub install_file {
    my ($install_document, $install_policy, $path, $name) = @_;

    my $archive = "$ROOT/$name.tar.gz";
    my ($manifest, $members) =
        HostArtifactsTest::artifact($install_document, { $path => { content => "$name\n" } });
    HostArtifactsTest::write_archive(
        $archive, [{ name => 'manifest.json', content => $json->encode($manifest) }, @$members],
    );
    PVE::HostArtifacts::with_target_lock(
        $install_policy->{target},
        sub {
            PVE::HostArtifacts::install_verified_archive(
                $install_policy, HostArtifactsTest::request($archive), $archive,
                "UPID:test:$name", 'deploy@pve!install',
            );
        },
    );
}

install_file($document, $policy, $artifact_file, 'app');
install_file(
    $other_document, PVE::HostArtifacts::load_policy($other_target), $other_artifact_file,
    'other-app',
);
my $other_status = set_secret($other_target, $OTHER_FIELD, value('other'), 1);
$check->('the unrelated target sets its field', $other_status eq 'OK', $other_status);
my ($stopped_target, $stopped_paths) = HostArtifactsTest::interrupted_target(
    'suburban/secret-stopped', "$ROOT/stopped",
);

# The function returns the unrelated state that every request for the selected field leaves
# unchanged.
sub unrelated_state {
    return $json->encode({
        artifact => file_state($artifact_file),
        installed => read_or_absent("$STATE_DIR/$target/installed.json"),
        other_target => HostArtifactsTest::target_state(
            $other_target, $other_artifact_file, $other_secret_file,
        ),
        stopped_target => HostArtifactsTest::target_state($stopped_target, @$stopped_paths),
        other_consumer => unit_property($OTHER_CONSUMER, 'InvocationID'),
        unrelated => unit_property($UNRELATED, 'InvocationID'),
    });
}
my $unrelated_before = unrelated_state();
my $check_unrelated = sub {
    my ($label) = @_;

    $check->(
        "the files, records, journals, and lock files of the unrelated targets and the"
            . " InvocationID values of the unrelated consumer units stay unchanged after $label",
        unrelated_state() eq $unrelated_before,
    );
};

# The tests check callers without Sys.HostSecrets.Modify.

for my $user ('auditor@pve', 'deploy@pve!audit', 'deploy@pve!install') {
    my $response = secret_request($user, $target, $FIELD, value('denied'), 1);
    $check->("$user cannot set a secret", $response->{status} == 403);
}
$check->('the denied requests do not create the storage file', !-e $secret_file);
$check_unrelated->('the denied requests');

# The tests check version 1.

my $consumer_before = unit_property($CONSUMER, 'InvocationID');
my $status = set_secret($target, $FIELD, value('one'), 1);
$check->('version 1 succeeds', $status eq 'OK', $status);
$check->(
    'the storage file contains the field and the value',
    HostArtifactsTest::read_file($secret_file) eq "$FIELD=" . value('one') . "\n",
);
my @secret_stat = lstat($secret_file);
$check->(
    'the storage file has mode 0600 and owner root',
    ($secret_stat[2] & 07777) == 0600 && $secret_stat[4] == 0 && $secret_stat[5] == 0,
);
my $state = secret_state($target, $FIELD);
$check->(
    'GET reports only the field, configured, restart_pending, version, and SHA-256',
    join(',', sort keys %$state) eq 'configured,field,restart_pending,sha256,version',
);
$check->('GET reports restart_pending 0 after version 1', $state->{restart_pending} eq '0');
$check->(
    'GET reports version 1 and the SHA-256 of the storage file',
    $state->{configured}
        && $state->{version} == 1
        && $state->{sha256} eq content_sha($FIELD, value('one')),
);
$check->(
    'version 1 restarts the consumer',
    unit_property($CONSUMER, 'InvocationID') ne $consumer_before,
);
$check->('the consumer receives version 1', received() eq received_value('one'));
$check_unrelated->('version 1');

# The tests check an exact retry of version 1.

my $file_before = file_state($secret_file);
$consumer_before = unit_property($CONSUMER, 'InvocationID');
$status = set_secret($target, $FIELD, value('one'), 1);
$check->('an exact retry of version 1 succeeds', $status eq 'OK', $status);
$check->(
    'an exact retry leaves the storage file unchanged',
    file_state($secret_file) eq $file_before,
);
$check->(
    'an exact retry does not restart the consumer',
    unit_property($CONSUMER, 'InvocationID') eq $consumer_before,
);
$check_unrelated->('an exact retry');

# The tests check another value at version 1, version 2, and a lower version.

my $record_before = $json->encode(secret_record($target, $FIELD));
$status = set_secret($target, $FIELD, value('two'), 1);
$check_match->('another value at version 1 fails', $status, qr/already has another value/);
$check->(
    'the failed request leaves the storage file unchanged',
    file_state($secret_file) eq $file_before,
);
$check->(
    'the failed request leaves the record unchanged',
    $json->encode(secret_record($target, $FIELD)) eq $record_before,
);

$status = set_secret($target, $FIELD, value('two'), 2);
$check->('version 2 succeeds', $status eq 'OK', $status);
$check->(
    'version 2 restarts the consumer',
    unit_property($CONSUMER, 'InvocationID') ne $consumer_before,
);
$check->('the consumer receives version 2', received() eq received_value('two'));
$check->('GET reports version 2', secret_state($target, $FIELD)->{version} == 2);

$file_before = file_state($secret_file);
$consumer_before = unit_property($CONSUMER, 'InvocationID');
$status = set_secret($target, $FIELD, value('one'), 1);
$check_match->('a lower version fails', $status, qr/lower than the stored version 2/);
$check->(
    'the lower version leaves the storage file unchanged',
    file_state($secret_file) eq $file_before,
);
$check->(
    'the lower version does not restart the consumer',
    unit_property($CONSUMER, 'InvocationID') eq $consumer_before,
);
$check_unrelated->('version 2 and the rejected versions');

# The tests check unsupported fields, extra parameters, and invalid values.

my $unsupported = secret_request($SECRET_TOKEN, $target, $OTHER_FIELD, value('three'), 3);
$check_match->(
    'a field that the policy does not list fails',
    $unsupported->{message},
    qr/does not list the secret field $OTHER_FIELD/,
);
my $lowercase = secret_request($SECRET_TOKEN, $target, 'lower_case', value('three'), 3);
$check->('a field name that does not match the schema fails', $lowercase->{status} == 400);
my $extra = HostArtifactsTest::api_request(
    $rpcenv, $SECRET_TOKEN, 'PUT', "$target/secrets/$FIELD",
    { value => value('three'), version => 3, mode => '0644' },
);
push @messages, ($extra->{message} // '') . $json->encode($extra->{errors} // {});
$check->('an extra parameter fails', $extra->{status} == 400);

my $invalid_values = {
    newline => "$MARKER-value\nINJECTED=1",
    'command substitution' => "$MARKER-\$(id)-value",
    quote => "$MARKER-'value'",
    '[email]' => "$MARKER-[email]-value",
    'too few characters' => 'short',
    'more than 512 characters' => "$MARKER-" . ('a' x 520),
};
for my $label (sort keys %$invalid_values) {
    my $response =
        secret_request($SECRET_TOKEN, $target, $FIELD, $invalid_values->{$label}, 3);
    $check->("a value with $label fails", $response->{status} != 200);
}
$check->(
    'the invalid values leave the storage file unchanged',
    file_state($secret_file) eq $file_before,
);
$check->('GET still reports version 2', secret_state($target, $FIELD)->{version} == 2);
$check_unrelated->('the rejected requests');

# The tests check drift of the storage file.

HostArtifactsTest::write_file($secret_file, "$FIELD=changed-outside-the-api\n", 0600);
$check->(
    'GET reports the SHA-256 of the changed storage file',
    secret_state($target, $FIELD)->{sha256} ne content_sha($FIELD, value('two')),
);
$consumer_before = unit_property($CONSUMER, 'InvocationID');
$status = set_secret($target, $FIELD, value('two'), 2);
$check->('a retry of version 2 repairs the changed file', $status eq 'OK', $status);
$check->(
    'the repaired file contains version 2',
    secret_state($target, $FIELD)->{sha256} eq content_sha($FIELD, value('two')),
);
$check->(
    'the repair restarts the consumer',
    unit_property($CONSUMER, 'InvocationID') ne $consumer_before,
);
$check_unrelated->('the drift repair');

# The tests check drift of the storage file mode and owner.

for my $drift (
    ['mode', sub { chmod(0644, $secret_file) or die "cannot change $secret_file: $!\n" }],
    ['owner', sub { chown(1, 1, $secret_file) or die "cannot change $secret_file: $!\n" }],
) {
    my ($kind, $change) = @$drift;
    $change->();
    my $drifted = file_state($secret_file);
    my $drift_state = secret_state($target, $FIELD);
    $check->(
        "GET reports that a storage file with another $kind does not match the policy",
        !$drift_state->{configured},
    );
    $check->(
        "GET reports the content SHA-256 of a storage file with another $kind",
        $drift_state->{sha256} eq content_sha($FIELD, value('two')),
    );
    $check->(
        "GET leaves the storage file with another $kind unchanged",
        file_state($secret_file) eq $drifted,
    );
    $consumer_before = unit_property($CONSUMER, 'InvocationID');
    my $inode_before = (lstat($secret_file))[1];
    $status = set_secret($target, $FIELD, value('two'), 2);
    $check->("a retry of version 2 repairs the $kind", $status eq 'OK', $status);
    my @repaired = lstat($secret_file);
    $check->(
        "the repair restores mode 0600 and owner root",
        ($repaired[2] & 07777) == 0600 && $repaired[4] == 0 && $repaired[5] == 0,
    );
    $check->("the $kind repair keeps the inode of the storage file", $repaired[1] == $inode_before);
    $check->(
        "the $kind repair does not restart the consumer",
        unit_property($CONSUMER, 'InvocationID') eq $consumer_before,
    );
    $check->(
        'GET reports the repaired storage file as configured',
        secret_state($target, $FIELD)->{configured},
    );
    $check_unrelated->("the $kind repair");
}

# The tests check a failed consumer restart and its retry.

HostArtifactsTest::write_file("$ROOT/state/fail", '');
$status = set_secret($target, $FIELD, value('three'), 3);
$check_match->(
    'version 3 fails when the consumer restart fails',
    $status,
    qr/systemctl restart \Q$CONSUMER\E failed/,
);
$check->(
    'the failed restart leaves version 3 in the file',
    secret_state($target, $FIELD)->{sha256} eq content_sha($FIELD, value('three')),
);
$check->(
    'the record keeps the restart of the consumer',
    join(',', @{ secret_record($target, $FIELD)->{pending} }) eq $CONSUMER,
);
$check->(
    'GET reports restart_pending 1 after the failed restart',
    secret_state($target, $FIELD)->{restart_pending} eq '1',
);

# The function returns the storage file and secret record state of the selected target.
sub secret_files_state {
    return join(' ', file_state($secret_file), file_state("$STATE_DIR/$target/secrets.json"));
}

my $files_before_get = secret_files_state();
my $audit_response =
    HostArtifactsTest::api_request($rpcenv, 'deploy@pve!audit', 'GET', $target, {});
my ($audit_state) = grep { $_->{field} eq $FIELD } @{ $audit_response->{data}->{secrets} // [] };
$check->(
    'GET reports restart_pending 1 for an audit-only token',
    $audit_response->{status} == 200 && $audit_state->{restart_pending} eq '1',
);
my $audit_text = $json->encode($audit_response->{data});
$check->(
    'the audit response does not contain the value or a unit name',
    index($audit_text, $MARKER) < 0 && index($audit_text, $CONSUMER) < 0,
);
$check->(
    'GET does not change the storage file or the secret record while a restart is pending',
    secret_files_state() eq $files_before_get,
);
unlink("$ROOT/state/fail") or die "cannot delete $ROOT/state/fail: $!\n";
chmod(0644, $secret_file) or die "cannot change $secret_file: $!\n";
$consumer_before = unit_property($CONSUMER, 'InvocationID');
$status = set_secret($target, $FIELD, value('three'), 3);
$check->('a retry of version 3 succeeds', $status eq 'OK', $status);
$check->(
    'the retry restores the mode and keeps the recorded restart',
    ((lstat($secret_file))[2] & 07777) == 0600,
);
$check->(
    'the retry restarts the consumer',
    unit_property($CONSUMER, 'InvocationID') ne $consumer_before
        && unit_property($CONSUMER, 'ActiveState') eq 'active',
);
$check->('the consumer receives version 3', received() eq received_value('three'));
$check->('the retry clears the restart', !@{ secret_record($target, $FIELD)->{pending} });
$check->(
    'GET reports restart_pending 0 after the retry of version 3',
    secret_state($target, $FIELD)->{restart_pending} eq '0',
);
$check_unrelated->('the failed restart and its retry');

# The tests check an interrupted task and its recovery.

# The function starts a rotation, kills the task process group while the consumer restart
# waits, and lets the consumer finish its start.
sub interrupt_rotation {
    my ($label, $version) = @_;

    HostArtifactsTest::write_file("$ROOT/state/hold", '');
    my $interrupted = secret_request($SECRET_TOKEN, $target, $FIELD, value($label), $version);
    die "the secret request returned status $interrupted->{status}\n"
        if $interrupted->{status} != 200;
    push @upids, $interrupted->{data};
    wait_for_state($CONSUMER, 'activating');
    my ($task) = PVE::Tools::upid_decode($interrupted->{data});
    die "the task has an unexpected process ID\n" if $task->{pid} !~ m/\A([0-9]+)\z/;
    my $task_pid = $1;
    kill('KILL', -$task_pid);
    HostArtifactsTest::wait_for_task($interrupted->{data});
    $check->(
        "the stopped task records version $version and the consumer restart",
        secret_record($target, $FIELD)->{version} == $version
            && join(',', @{ secret_record($target, $FIELD)->{pending} }) eq $CONSUMER,
    );
    $check->(
        "GET reports restart_pending 1 after the stopped task of version $version",
        secret_state($target, $FIELD)->{restart_pending} eq '1',
    );
    unlink("$ROOT/state/hold") or die "cannot delete $ROOT/state/hold: $!\n";
    wait_for_state($CONSUMER, 'active');
}

interrupt_rotation('four', 4);
$consumer_before = unit_property($CONSUMER, 'InvocationID');
$status = set_secret($target, $FIELD, value('four'), 4);
$check->('a retry of version 4 succeeds', $status eq 'OK', $status);
$check->(
    'the retry completes the restart of the consumer',
    unit_property($CONSUMER, 'InvocationID') ne $consumer_before,
);
$check->('the consumer receives version 4', received() eq received_value('four'));
$check->('the retry clears the restart', !@{ secret_record($target, $FIELD)->{pending} });
$check->(
    'GET reports restart_pending 0 after the retry of version 4',
    secret_state($target, $FIELD)->{restart_pending} eq '0',
);
$check_unrelated->('the interrupted task and its recovery');

# The tests check a retry after an operator stops the consumer.

interrupt_rotation('five', 5);
run_systemctl('stop', $CONSUMER);
$check->('the operator stops the consumer', unit_property($CONSUMER, 'ActiveState') eq 'inactive');
my $stopped_response = secret_request($SECRET_TOKEN, $target, $FIELD, value('five'), 5);
die "the secret request returned status $stopped_response->{status}\n"
    if $stopped_response->{status} != 200;
push @upids, $stopped_response->{data};
my ($stopped_status, $stopped_log) = HostArtifactsTest::wait_for_task($stopped_response->{data});
$check->('a retry of version 5 succeeds', $stopped_status eq 'OK', $stopped_status);
$check->(
    'the retry does not start the stopped consumer',
    unit_property($CONSUMER, 'ActiveState') eq 'inactive',
);
$check_match->(
    'the task log records the stopped consumer state',
    $stopped_log,
    qr/the consumer unit \Q$CONSUMER\E is inactive, and the task does not start it/,
);
$check->('the retry clears the restart', !@{ secret_record($target, $FIELD)->{pending} });
$check->(
    'the storage file contains version 5',
    secret_state($target, $FIELD)->{sha256} eq content_sha($FIELD, value('five')),
);
run_systemctl('start', $CONSUMER);
$check_unrelated->('the retry after an operator stop');

# The tests check a recorded restart of a unit that the policy does not list anymore.

HostArtifactsTest::write_file("$ROOT/state/fail", '');
$status = set_secret($target, $FIELD, value('six'), 6);
$check_match->(
    'the request for version 6 fails when the consumer restart fails',
    $status,
    qr/systemctl restart \Q$CONSUMER\E failed/,
);
unlink("$ROOT/state/fail") or die "cannot delete $ROOT/state/fail: $!\n";
$secret_descriptor->{consumer_units} = [$OTHER_POLICY_UNIT];
HostArtifactsTest::write_policy($document);
$check->(
    'GET reports restart_pending 0 when the policy does not list the recorded unit',
    secret_state($target, $FIELD)->{restart_pending} eq '0'
        && join(',', @{ secret_record($target, $FIELD)->{pending} }) eq $CONSUMER,
);
$secret_descriptor->{consumer_units} = [$CONSUMER];
HostArtifactsTest::write_policy($document);
$check->(
    'GET reports restart_pending 1 when the policy lists the recorded unit again',
    secret_state($target, $FIELD)->{restart_pending} eq '1',
);
$status = set_secret($target, $FIELD, value('six'), 6);
$check->('a retry of version 6 succeeds', $status eq 'OK', $status);
$check->(
    'GET reports restart_pending 0 after the retry of version 6',
    secret_state($target, $FIELD)->{restart_pending} eq '0',
);
$check_unrelated->('the recorded restart of an unlisted unit');

# The stopped target keeps its journal and uses that journal to restore its files.

PVE::HostArtifacts::with_target_lock(
    $stopped_target, sub { PVE::HostArtifacts::recover($stopped_target) },
);
$check->(
    'the stopped target restores its files from its own journal',
    !-e "$STATE_DIR/$stopped_target/journal.json" && !grep { -e $_ } @$stopped_paths,
);

# The tests check logs, responses, and records.

my $task_logs = 0;
my $marked_logs = 0;
for my $upid (@upids) {
    my (undef, $log_path) = PVE::Tools::upid_decode($upid);
    next if !-e $log_path;
    $task_logs++;
    $marked_logs++ if index(HostArtifactsTest::read_file($log_path), $MARKER) >= 0;
}
$check->(
    "the marker does not appear in $task_logs task logs",
    $task_logs > 0 && !$marked_logs,
);
$check->('the marker does not appear in a UPID', !grep { index($_, $MARKER) >= 0 } @upids);
$check->(
    'the marker does not appear in a response message',
    !grep { index($_, $MARKER) >= 0 } @messages,
);
$check->(
    'the marker does not appear in a secret record',
    index(read_or_absent("$STATE_DIR/$target/secrets.json"), $MARKER) < 0,
);
open(my $journal, '-|', $JOURNALCTL, '--no-pager', '--output=cat')
    or die "cannot run journalctl: $!\n";
my $journal_lines = 0;
my $marked_lines = 0;
while (my $line = <$journal>) {
    $journal_lines++;
    $marked_lines++ if index($line, $MARKER) >= 0;
}
close($journal);
$check->(
    "the marker does not appear in $journal_lines journal lines",
    $journal_lines > 0 && !$marked_lines,
);

# The tests check the cleanup.

run_systemctl('stop', $CONSUMER, $OTHER_CONSUMER, $UNRELATED);
for my $unit ($CONSUMER, $OTHER_CONSUMER, $UNRELATED) {
    unlink("$UNIT_DIR/$unit") or die "cannot delete $UNIT_DIR/$unit: $!\n";
}
run_systemctl('daemon-reload');
$check->(
    'the cleanup removes the test units',
    unit_property($CONSUMER, 'LoadState') eq 'not-found'
        && unit_property($UNRELATED, 'LoadState') eq 'not-found',
);
remove_tree($ROOT);
$check->('the cleanup removes the test files', !-e $ROOT);

print "all tests passed\n";

exit(0);
