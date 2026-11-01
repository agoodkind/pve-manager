#!/usr/bin/perl -T

# The test runs the host artifact module and API methods against the real file system. It writes
# below /etc/pve-overlay, /var/lib/pve-overlay, and /srv and must run as root in a disposable
# container. The access control patch of the overlay must be applied, because the ACL file
# uses the Sys.HostArtifacts privileges.

use strict;
use warnings;

use lib qw(.. .);

use Digest::SHA;
use File::Path qw(make_path remove_tree);
use MIME::Base64 qw(encode_base64);
use POSIX qw();
use Time::HiRes qw();

use PVE::HostArtifacts;
use PVE::INotify;
use PVE::RPCEnvironment;

use HostArtifactsTest;

delete @ENV{qw(PATH IFS CDPATH ENV BASH_ENV)};

HostArtifactsTest::require_disposable_root();

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'host-artifacts-test.cfg');

my $ROOT = '/srv/host-artifacts-test';
my $WORK = '/srv/host-artifacts-test-work';
my $STATE_DIR = '/var/lib/pve-overlay/host-artifacts';
my $TOKEN = 'deploy@pve!install';
my $INTERRUPT_FILE_COUNT = 300;
my $INTERRUPT_ATTEMPTS = 5;
my $OLD_STAGE_SECONDS = 7200;

remove_tree($ROOT, $WORK);
make_path("$ROOT/etc", "$ROOT/many", $WORK, { mode => 0755 });
HostArtifactsTest::write_file(
    PVE::HostArtifacts::trusted_root_path(), "{\"mediaType\":\"test\"}\n",
);

my $check = \&HostArtifactsTest::check;
my $check_error = \&HostArtifactsTest::check_error;
my $check_match = \&HostArtifactsTest::check_match;
my $json = HostArtifactsTest::json();
my $upid_counter = 0;

sub next_upid {
    $upid_counter++;
    return "UPID:test:$upid_counter";
}

# Returns the content, inode, mode, owner, group, modification time, and change time of each
# path.
sub snapshot {
    my (@paths) = @_;

    return file_state([1, 2, 4, 5, 9, 10], @paths);
}

# Returns the state of each path without the change time. A hard link and a rename change the
# change time of a restored file.
sub content_snapshot {
    my (@paths) = @_;

    return file_state([1, 2, 4, 5, 9], @paths);
}

sub file_state {
    my ($fields, @paths) = @_;

    my $state = {};
    for my $path (@paths) {
        my @stat = lstat($path);
        if (!@stat) {
            $state->{$path} = 'absent';
            next;
        }
        my $digest = Digest::SHA->new(256)->addfile($path)->hexdigest();
        $state->{$path} = join(':', $digest, @stat[@$fields]);
    }
    return $json->encode($state);
}

sub write_artifact {
    my ($name, $manifest, $members) = @_;

    my $path = "$WORK/$name.tar.gz";
    HostArtifactsTest::write_archive(
        $path,
        [{ name => 'manifest.json', content => $json->encode($manifest) }, @$members],
    );
    return $path;
}

sub install_archive {
    my ($policy, $archive_path, %request_override) = @_;

    my $request = HostArtifactsTest::request($archive_path, %request_override);
    my $upid = next_upid();
    PVE::HostArtifacts::with_target_lock(
        $policy->{target},
        sub {
            PVE::HostArtifacts::install_verified_archive(
                $policy, $request, $archive_path, $upid, $TOKEN,
            );
        },
    );
    return $upid;
}

sub get_state {
    my ($target, $user) = @_;

    my $response =
        HostArtifactsTest::api_request($rpcenv, $user // $TOKEN, 'GET', $target, {});
    die "GET returned status $response->{status}: " . ($response->{message} // '') . "\n"
        if $response->{status} != 200;
    return $response->{data};
}

sub files_by_path {
    my ($state) = @_;

    return { map { $_->{path} => $_ } @{ $state->{files} } };
}

sub list_leftovers {
    my ($dir) = @_;

    opendir(my $handle, $dir) or die "cannot read $dir: $!\n";
    my @leftovers = grep { m/pve-overlay/ } readdir($handle);
    closedir($handle);
    return @leftovers;
}

sub stage_record_path {
    my ($target, $stage) = @_;

    return "$STATE_DIR/$target/stages/$stage.json";
}

# Interrupts an install of $archive_path in a child process after the first file changes, and
# returns the number of files with the new content.
sub interrupt_install {
    my ($policy, $archive_path, $paths, %request_override) = @_;

    my $first_inode = (lstat($paths->[0]))[1];
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        open(STDOUT, '>', '/dev/null') or POSIX::_exit(2);
        eval { install_archive($policy, $archive_path, %request_override) };
        POSIX::_exit($@ ? 1 : 0);
    }
    my $deadline = Time::HiRes::time() + 120;
    while (Time::HiRes::time() < $deadline) {
        my $inode = (lstat($paths->[0]))[1] // $first_inode;
        last if $inode != $first_inode;
        last if waitpid($pid, POSIX::WNOHANG()) == $pid;
        Time::HiRes::sleep(0.0005);
    }
    kill('KILL', $pid);
    waitpid($pid, 0);
    return scalar(grep { HostArtifactsTest::read_file($_) =~ m/\Atwo / } @$paths);
}

# The function starts an install of $archive_path in a child process, sends $signal to the
# child when $ready returns true, and returns the error of the child. The child dies on TERM,
# as a task worker of fork_worker does.
sub stop_install {
    my ($policy, $archive_path, $signal, $ready) = @_;

    pipe(my $reader, my $writer) or die "cannot create a pipe: $!\n";
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        close($reader);
        open(STDOUT, '>', '/dev/null') or POSIX::_exit(2);
        local $SIG{TERM} = sub { die "received interrupt\n" };
        eval { install_archive($policy, $archive_path) };
        print {$writer} ($@ // '');
        close($writer);
        POSIX::_exit(0);
    }
    close($writer);
    my $deadline = Time::HiRes::time() + 120;
    while (Time::HiRes::time() < $deadline) {
        last if $ready->();
        last if waitpid($pid, POSIX::WNOHANG()) == $pid;
        Time::HiRes::sleep(0.0005);
    }
    kill($signal, $pid);
    my $error = do { local $/ = undef; <$reader> } // '';
    close($reader);
    waitpid($pid, 0);
    return $error;
}

sub new_target {
    my ($workspace, $files, $directories, $parents) = @_;

    my $document = HostArtifactsTest::base_policy($workspace, $files, $directories);
    $document->{parent_directories} = $parents if $parents;
    my $target = HostArtifactsTest::write_policy($document);
    return ($document, PVE::HostArtifacts::load_policy($target));
}

sub directory_mode {
    my ($path) = @_;

    my @stat = lstat($path);
    return 'absent' if !@stat;
    return sprintf('%04o', $stat[2] & 07777);
}

sub file_entries {
    my ($paths, %metadata) = @_;

    return [map { { path => $_, mode => '0644', owner => 'root', group => 'root', %metadata } }
        @$paths];
}

sub contents {
    my ($paths, $prefix) = @_;

    return { map { $_ => { content => "$prefix $_\n" } } @$paths };
}

sub count_with_prefix {
    my ($paths, $prefix) = @_;

    return scalar(grep { -e $_ && HostArtifactsTest::read_file($_) =~ m/\A\Q$prefix\E / }
        @$paths);
}

sub program_entry {
    my ($name, %override) = @_;

    return {
        name => $name,
        repository => 'agoodkind/example',
        workflow_uri => 'https://github.com/agoodkind/example/.github/workflows/release.yml'
            . '@refs/heads/main',
        source_ref => 'refs/heads/main',
        path => "$ROOT/programs/$name",
        mode => '0755',
        owner => 'root',
        group => 'root',
        max_archive_bytes => 100,
        max_bundle_bytes => 50,
        %override,
    };
}

sub program_stage_request {
    my ($user, $target, $kind, $program, $content) = @_;

    my $params = { kind => $kind, offset => 0, data => encode_base64($content, '') };
    $params->{program} = $program if defined($program);
    return HostArtifactsTest::api_request($rpcenv, $user, 'POST', "$target/stage", $params);
}

sub stage_program {
    my ($user, $target, $kind, $program, $content) = @_;

    my $response = program_stage_request($user, $target, $kind, $program, $content);
    die "staging failed with status $response->{status}: " . ($response->{message} // '') . "\n"
        if $response->{status} != 200;
    return $response->{data}->{stage};
}

# Workspace selectors and target identity.

for my $selector (
    'suburban/mwan', 'suburban/simulators/astound', 'suburban/mwan_test', 'a', 'x y/z',
) {
    my $target = PVE::HostArtifacts::target_of_workspace($selector);
    $check->(
        "selector '$selector' maps to its SHA-256",
        $target eq Digest::SHA::sha256_hex($selector),
    );
}
for my $selector (
    '', '/abs', 'a//b', 'a/', '.hidden', 'a/./b', 'a/../b', 'modules/x', 'a/terraform.d',
    'a\\b',
) {
    $check_error->(
        "selector '$selector' is rejected",
        sub { PVE::HostArtifacts::check_workspace_selector($selector) },
        qr/workspace selector/,
    );
}

# The selected target and an invalid unrelated policy.

my $files_policy = [
    { path => "$ROOT/etc/a.conf", mode => '0644', owner => 'root', group => 'root' },
    { path => "$ROOT/etc/b.conf", mode => '0640', owner => 'root', group => 'daemon' },
    { path => "$ROOT/etc/c.conf", mode => '0600', owner => 'root', group => 'root' },
    { path => "$ROOT/etc/new/d.conf", mode => '0644', owner => 'root', group => 'root' },
];
my $directories_policy =
    [{ path => "$ROOT/etc/new", mode => '0750', owner => 'root', group => 'daemon' }];
my $policy_document = HostArtifactsTest::base_policy(
    'suburban/host_artifact_test', $files_policy, $directories_policy,
);
my $target = HostArtifactsTest::write_policy($policy_document);
my $invalid_target = PVE::HostArtifacts::target_of_workspace('suburban/unrelated');
HostArtifactsTest::write_file(
    PVE::HostArtifacts::policy_path($invalid_target), "this is not JSON\n",
);
my $policy = PVE::HostArtifacts::load_policy($target);
$check->(
    'the selected policy loads beside an invalid unrelated policy',
    $policy->{target} eq $target,
);

my $initial_state = get_state($target);
$check->('GET reports none before an install', $initial_state->{state} eq 'none');
$check->(
    'GET reports a null installed record before an install',
    exists($initial_state->{installed}) && !defined($initial_state->{installed}),
);
$check->(
    'GET lists the policy files before an install',
    scalar(@{ $initial_state->{files} }) == 4,
);

# Policy identity checks.

my $mismatched_target = PVE::HostArtifacts::target_of_workspace('suburban/other');
HostArtifactsTest::write_policy($policy_document, $mismatched_target);
$check_error->(
    'a policy with the workspace of another target is rejected',
    sub { PVE::HostArtifacts::load_policy($mismatched_target) },
    qr/has the target \Q$target\E, not \Q$mismatched_target\E/,
);

my $other_node_document =
    { %$policy_document, workspace => 'suburban/other-node', node => 'othernode' };
my $other_node_target = HostArtifactsTest::write_policy($other_node_document);
my $other_node_response =
    HostArtifactsTest::api_request($rpcenv, $TOKEN, 'GET', $other_node_target, {});
$check->('GET fails for a policy of another node', $other_node_response->{status} != 200);
$check_match->(
    'GET reports the node of the policy',
    $other_node_response->{message},
    qr/is for node 'othernode'/,
);

my $missing_target = PVE::HostArtifacts::target_of_workspace('suburban/missing');
my $missing_response =
    HostArtifactsTest::api_request($rpcenv, $TOKEN, 'GET', $missing_target, {});
$check_match->(
    'GET reports the path of the missing policy file',
    $missing_response->{message},
    qr/\Q$missing_target\E\.json does not exist/,
);

# The tests create two unrelated targets. One target has a committed install. The install of
# the other target stops, and that target keeps its journal. After each install, rejection, and
# recovery of another target, the tests compare the files, installed record, secret record,
# journal, and lock file of both targets.

my $unrelated_dir = "$ROOT/unrelated";
my $unrelated_file = "$unrelated_dir/u.conf";
my $unrelated_document = HostArtifactsTest::base_policy(
    'suburban/observation-unrelated',
    [{ path => $unrelated_file, mode => '0644', owner => 'root', group => 'root' }],
    [{ path => $unrelated_dir, mode => '0750', owner => 'root', group => 'root' }],
);
my $unrelated_target = HostArtifactsTest::write_policy($unrelated_document);
my $unrelated_policy = PVE::HostArtifacts::load_policy($unrelated_target);
my $unrelated_archive = write_artifact(
    'unrelated',
    HostArtifactsTest::artifact(
        $unrelated_document, { $unrelated_file => { content => "u\n" } },
    ),
);
install_archive($unrelated_policy, $unrelated_archive);
my ($stopped_target, $stopped_paths) = HostArtifactsTest::interrupted_target(
    'suburban/observation-stopped', "$ROOT/stopped",
);

sub unrelated_state {
    return $json->encode([
        HostArtifactsTest::target_state($unrelated_target, $unrelated_dir, $unrelated_file),
        HostArtifactsTest::target_state($stopped_target, @$stopped_paths),
    ]);
}
my $unrelated_before = unrelated_state();
my $check_unrelated = sub {
    my ($label) = @_;

    $check->(
        "the files, records, journals, and lock files of the unrelated targets stay unchanged"
            . " after $label",
        unrelated_state() eq $unrelated_before,
    );
};

# The first install.

my $version_one = {
    "$ROOT/etc/a.conf" => { content => "a one\n" },
    "$ROOT/etc/b.conf" => { content => "b one\n", mode => '0640', group => 'daemon' },
    "$ROOT/etc/c.conf" => { content => "c one\n", mode => '0600' },
    "$ROOT/etc/new/d.conf" => { content => "d one\n" },
};
my ($manifest_one, $members_one) = HostArtifactsTest::artifact($policy_document, $version_one);
my $archive_one = write_artifact('one', $manifest_one, $members_one);
my $first_upid = install_archive($policy, $archive_one);

my $state = get_state($target);
my $files = files_by_path($state);
$check->('GET reports committed after the install', $state->{state} eq 'committed');
$check->('GET reports the install UPID', $state->{installed}->{upid} eq $first_upid);
for my $path (sort keys %$version_one) {
    my $expected = $version_one->{$path};
    my $file = $files->{$path};
    $check->("$path matches", $file->{matches} && $file->{present});
    $check->(
        "$path has the archive content",
        HostArtifactsTest::read_file($path) eq $expected->{content},
    );
    $check->("$path has mode $file->{mode}", $file->{mode} eq ($expected->{mode} // '0644'));
    $check->("$path has the group", $file->{group} eq ($expected->{group} // 'root'));
    $check->("$path has the install write_id", $file->{write_id} eq $first_upid);
}
my @new_dir_stat = lstat("$ROOT/etc/new");
$check->(
    'the install created the directory with its policy mode and group',
    sprintf('%04o', $new_dir_stat[2] & 07777) eq '0750'
        && $new_dir_stat[5] == scalar(getgrnam('daemon')),
);
$check_unrelated->('the first install');

# An identical install writes only the installed record.

my @all_paths = sort keys %$version_one;
my $before_repeat = snapshot(@all_paths);
my $installed_path = "$STATE_DIR/$target/installed.json";
my $installed_before = HostArtifactsTest::read_file($installed_path);
Time::HiRes::sleep(1.1);
my $repeat_upid = install_archive($policy, $archive_one);
$check->(
    'an identical install leaves every file unchanged',
    snapshot(@all_paths) eq $before_repeat,
);
$check->(
    'an identical install rewrites the installed record',
    HostArtifactsTest::read_file($installed_path) ne $installed_before,
);
$check->('an identical install leaves no journal', !-e "$STATE_DIR/$target/journal.json");
$state = get_state($target);
$check->(
    'the installed record has the repeat UPID',
    $state->{installed}->{upid} eq $repeat_upid,
);
$check->(
    'an identical install keeps every write_id',
    !grep { $_->{write_id} ne $first_upid } @{ $state->{files} },
);
my @leftovers = list_leftovers("$ROOT/etc");
$check->('an install leaves no temporary or backup file', !@leftovers, "@leftovers");
$check_unrelated->('an identical install');

# Drift readback.

my $clean_digest = $state->{observed_sha256};
HostArtifactsTest::write_file("$ROOT/etc/a.conf", "a changed\n");
unlink("$ROOT/etc/b.conf") or die "cannot delete $ROOT/etc/b.conf: $!\n";
my $before_read = snapshot(@all_paths);
$state = get_state($target);
$check->('GET does not change a file', snapshot(@all_paths) eq $before_read);
$files = files_by_path($state);
$check->('GET reports the changed file', !$files->{"$ROOT/etc/a.conf"}->{matches});
$check->(
    'GET reports the SHA-256 of the changed file',
    $files->{"$ROOT/etc/a.conf"}->{sha256} eq Digest::SHA::sha256_hex("a changed\n"),
);
$check->(
    'GET reports the missing file',
    !$files->{"$ROOT/etc/b.conf"}->{present} && !$files->{"$ROOT/etc/b.conf"}->{matches},
);
$check->('GET reports the unchanged file', $files->{"$ROOT/etc/c.conf"}->{matches});
$check->('the observed digest changes with drift', $state->{observed_sha256} ne $clean_digest);
$check->(
    'the observed digest differs from the archive SHA-256',
    $state->{observed_sha256} ne $state->{installed}->{sha256},
);

# A repeat install repairs the drift and keeps the matching files.

my $c_before = snapshot("$ROOT/etc/c.conf");
my $repair_upid = install_archive($policy, $archive_one);
$state = get_state($target);
$files = files_by_path($state);
$check->('the repair restores every file', !grep { !$_->{matches} } @{ $state->{files} });
$check->(
    'the repair writes the changed file',
    $files->{"$ROOT/etc/a.conf"}->{write_id} eq $repair_upid,
);
$check->(
    'the repair writes the missing file',
    $files->{"$ROOT/etc/b.conf"}->{write_id} eq $repair_upid,
);
$check->(
    'the repair keeps the write_id of the matching file',
    $files->{"$ROOT/etc/c.conf"}->{write_id} eq $first_upid,
);
$check->(
    'the repair leaves the matching file unchanged',
    snapshot("$ROOT/etc/c.conf") eq $c_before,
);
$check->(
    'the observed digest returns to its clean value',
    $state->{observed_sha256} eq $clean_digest,
);
$check_unrelated->('the file drift repair');

# The tests check drift of an owned directory.

my $owned_new = "$ROOT/etc/new";
my $directory_entry = sub {
    my ($current) = @_;

    my ($entry) = grep { $_->{path} eq $owned_new } @{ $current->{directories} };
    return $entry;
};
$check->(
    'GET reports the owned directory as matching',
    $directory_entry->($state)->{matches} && $directory_entry->($state)->{mode} eq '0750',
);
my $directory_metadata = sub {
    return $json->encode([(lstat($owned_new))[1, 2, 4, 5]]);
};
my $write_ids = sub {
    my ($current) = @_;

    return $json->encode({ map { $_->{path} => $_->{write_id} } @{ $current->{files} } });
};
my $clean_directory = $directory_metadata->();
my $clean_write_ids = $write_ids->($state);
my $daemon_uid = getpwnam('daemon');
for my $drift (
    ['mode', sub { chmod(0755, $owned_new) }, 'mode', '0755'],
    ['owner', sub { chown($daemon_uid, -1, $owned_new) }, 'uid', $daemon_uid],
) {
    my ($kind, $change, $field, $value) = @$drift;
    $change->() or die "cannot change the $kind of $owned_new: $!\n";
    my $files_before_drift = snapshot(@all_paths);
    my $drifted_directory = $directory_metadata->();
    $state = get_state($target);
    $check->(
        "GET reports that an owned directory with another $kind does not match",
        !$directory_entry->($state)->{matches} && $directory_entry->($state)->{$field} eq $value,
    );
    $check->(
        "observed_sha256 changes when the owned directory $kind changes",
        $state->{observed_sha256} ne $clean_digest,
    );
    $check->(
        "GET does not change the owned directory with another $kind",
        $directory_metadata->() eq $drifted_directory,
    );
    install_archive($policy, $archive_one);
    $state = get_state($target);
    $check->(
        "a repeat install restores the owned directory $kind",
        $directory_metadata->() eq $clean_directory,
    );
    $check->(
        "GET reports the owned directory as matching after the $kind repair",
        $directory_entry->($state)->{matches},
    );
    $check->(
        "observed_sha256 equals its earlier clean value after the $kind repair",
        $state->{observed_sha256} eq $clean_digest,
    );
    $check->(
        "The $kind repair does not change any file",
        snapshot(@all_paths) eq $files_before_drift,
    );
    $check->(
        "Every file keeps its write_id after the $kind repair",
        $write_ids->($state) eq $clean_write_ids,
    );
    $check_unrelated->("the directory $kind drift and repair");
}

# Identity and member rejections. Every rejection leaves the files unchanged.

my $protected_paths = [@all_paths, $installed_path];

sub check_rejected {
    my ($label, $archive_path, $pattern, %request_override) = @_;

    my $before = snapshot(@$protected_paths);
    $check_error->(
        $label, sub { install_archive($policy, $archive_path, %request_override) }, $pattern,
    );
    $check->("$label leaves the files unchanged", snapshot(@$protected_paths) eq $before);
    $check_unrelated->("the rejection of $label");
}

my $version_two = { map { $_ => { %{ $version_one->{$_} } } } keys %$version_one };
$version_two->{"$ROOT/etc/a.conf"}->{content} = "a two\n";
my ($manifest_two, $members_two) = HostArtifactsTest::artifact($policy_document, $version_two);

my $variant = sub {
    my ($name, $manifest_change, $members_change) = @_;

    my $manifest = $json->decode($json->encode($manifest_two));
    my $members = [map { {%$_} } @$members_two];
    $manifest_change->($manifest) if $manifest_change;
    $members = $members_change->($members) if $members_change;
    return write_artifact($name, $manifest, $members);
};

my $replace_first_member = sub {
    my ($type, $linkname) = @_;

    return sub {
        my ($members) = @_;
        $members->[0] = { name => $members->[0]->{name}, type => $type, linkname => $linkname };
        return $members;
    };
};

check_rejected(
    'a manifest for another workspace',
    $variant->('workspace', sub { $_[0]->{workspace} = 'suburban/other' }),
    qr/manifest workspace is 'suburban\/other'/,
);
check_rejected(
    'a manifest for another node',
    $variant->('node', sub { $_[0]->{node} = 'othernode' }),
    qr/manifest node is 'othernode'/,
);
check_rejected(
    'a manifest for another environment',
    $variant->('environment', sub { $_[0]->{environment} = 'prod' }),
    qr/manifest environment is 'prod'/,
);
check_rejected(
    'a manifest from another repository',
    $variant->('repository', sub { $_[0]->{repository} = 'agoodkind/other' }),
    qr/manifest repository is 'agoodkind\/other'/,
);
check_rejected(
    'a manifest for another source revision',
    $variant->('revision', undef),
    qr/manifest source_revision is 'a{40}'/,
    source_revision => 'b' x 40,
);
check_rejected(
    'a manifest with an unknown field',
    $variant->('unknown', sub { $_[0]->{programs} = [] }),
    qr/unknown field 'programs'/,
);
check_rejected(
    'a directory member',
    $variant->(
        'directory', undef,
        sub { [@{ $_[0] }, { name => "files$ROOT/etc/dir", type => '5', mode => 0755 }] },
    ),
    qr/is not a regular file/,
);
check_rejected(
    'a symbolic link member',
    $variant->('symlink', undef, $replace_first_member->('2', '/etc/shadow')),
    qr/is not a regular file/,
);
check_rejected(
    'a hard link member',
    $variant->('hardlink', undef, $replace_first_member->('1', 'manifest.json')),
    qr/is not a regular file/,
);
check_rejected(
    'a member name with a parent component',
    $variant->(
        'traversal', undef,
        sub { [@{ $_[0] }, { name => 'files/../../etc/passwd', content => "x\n" }] },
    ),
    qr/has an empty, '\.', or '\.\.' component/,
);
check_rejected(
    'an absolute member name',
    $variant->(
        'absolute', undef, sub { [@{ $_[0] }, { name => '/etc/passwd', content => "x\n" }] },
    ),
    qr/has an absolute name/,
);
check_rejected(
    'an extra member',
    $variant->(
        'extra', undef,
        sub { [@{ $_[0] }, { name => "files$ROOT/etc/extra.conf", content => "x\n" }] },
    ),
    qr/is not in the manifest/,
);
check_rejected(
    'a missing member',
    $variant->('missing', undef, sub { [@{ $_[0] }[1 .. $#{ $_[0] }]] }),
    qr/does not contain the member/,
);
check_rejected(
    'a duplicate member',
    $variant->('duplicate', undef, sub { [@{ $_[0] }, $_[0]->[0]] }),
    qr/more than once/,
);
check_rejected(
    'a member with another size',
    $variant->('size', sub { $_[0]->{files}->[0]->{size} += 1 }),
    qr/has \d+ bytes, and the manifest lists/,
);
check_rejected(
    'a member with another SHA-256',
    $variant->(
        'digest', undef,
        sub {
            my ($members) = @_;
            $members->[0]->{content} =~ tr/a-z/b-za/;
            return $members;
        },
    ),
    qr/has SHA-256 [0-9a-f]{64}, and the manifest lists/,
);
check_rejected(
    'a member with special mode bits',
    $variant->(
        'member-mode', undef,
        sub {
            my ($members) = @_;
            $members->[0]->{mode} = 04755;
            return $members;
        },
    ),
    qr/has mode bits outside 0777/,
);
check_rejected(
    'a manifest mode with special bits',
    $variant->('manifest-mode', sub { $_[0]->{files}->[0]->{mode} = '4755' }),
    qr/does not match the required pattern/,
);
check_rejected(
    'a manifest mode that differs from the policy',
    $variant->('policy-mode', sub { $_[0]->{files}->[0]->{mode} = '0666' }),
    qr/does not match the mode, owner, and group in the policy/,
);

my ($outside_manifest, $outside_members) = HostArtifactsTest::artifact(
    $policy_document, { %$version_two, "$ROOT/etc/outside.conf" => { content => "x\n" } },
);
check_rejected(
    'a destination outside the policy',
    write_artifact('outside', $outside_manifest, $outside_members),
    qr/policy does not list the file \Q$ROOT\E\/etc\/outside\.conf/,
);
check_rejected(
    'a destination in the policy directory',
    $variant->(
        'protected', sub { $_[0]->{files}->[0]->{path} = '/etc/pve-overlay/host-artifacts/x' },
    ),
    qr/is inside \/etc\/pve-overlay/,
);
check_rejected(
    'a member that does not match its path',
    $variant->('member-name', sub { $_[0]->{files}->[0]->{member} = 'files/other' }),
    qr/manifest member of .* is 'files\/other'/,
);

my $gzip_tail = $variant->('tail', undef);
HostArtifactsTest::write_file($gzip_tail, HostArtifactsTest::read_file($gzip_tail) . 'garbage');
check_rejected('an archive with data after the gzip stream', $gzip_tail, qr/gzip|after its end/);

my $narrow_document = {
    %$policy_document,
    files => [grep { $_->{path} ne "$ROOT/etc/c.conf" } @$files_policy],
};
HostArtifactsTest::write_policy($narrow_document);
my $narrow_policy = PVE::HostArtifacts::load_policy($target);
my $narrow_archive = $variant->('narrow', undef);
my $narrow_before = snapshot(@$protected_paths);
$check_error->(
    'a policy that omits an artifact destination rejects the archive',
    sub { install_archive($narrow_policy, $narrow_archive) },
    qr/policy does not list the file \Q$ROOT\E\/etc\/c\.conf/,
);
$check->(
    'the omitted destination leaves the files unchanged',
    snapshot(@$protected_paths) eq $narrow_before,
);
HostArtifactsTest::write_policy($policy_document);

# The REST methods, the ACL, and the stage rules.

my $install_params_without_stages = {
    'release-tag' => 'hostconfig-test-202610300000-1-aaaaaaa',
    asset => 'hostconfig_test.tar.gz',
    sha256 => 'a' x 64,
    'source-revision' => 'a' x 40,
    'archive-stage' => '0' x 32,
    'bundle-stage' => '1' x 32,
};
for my $user ('auditor@pve', 'deploy@pve!audit') {
    my $stage_response = HostArtifactsTest::api_request(
        $rpcenv, $user, 'POST', "$target/stage", { kind => 'archive', offset => 0, data => '' },
    );
    $check->("the audit-only user $user cannot stage", $stage_response->{status} == 403);
    my $install_response = HostArtifactsTest::api_request(
        $rpcenv, $user, 'POST', $target, {%$install_params_without_stages},
    );
    $check->("the audit-only user $user cannot install", $install_response->{status} == 403);
    my $get_response = HostArtifactsTest::api_request($rpcenv, $user, 'GET', $target, {});
    $check->("the audit-only user $user can read", $get_response->{status} == 200);
}

my $archive_two = $variant->('two', undef);
my $archive_bytes = HostArtifactsTest::read_file($archive_two);
my $archive_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $target, 'archive', $archive_bytes);
$check->(
    'the stage file contains the uploaded bytes',
    HostArtifactsTest::read_file("$STATE_DIR/$target/stages/$archive_stage") eq $archive_bytes,
);
my $wrong_offset = HostArtifactsTest::api_request(
    $rpcenv, $TOKEN, 'POST', "$target/stage",
    { kind => 'archive', offset => 1, data => 'AAAA', stage => $archive_stage },
);
$check_match->(
    'a chunk at the wrong offset is rejected',
    $wrong_offset->{message},
    qr/does not equal the stage length/,
);
my $other_user = HostArtifactsTest::api_request(
    $rpcenv, 'deploy@pve', 'POST', "$target/stage",
    {
        kind => 'archive',
        offset => length($archive_bytes),
        data => 'AAAA',
        stage => $archive_stage,
    },
);
$check_match->(
    'another user cannot add to the stage',
    $other_user->{message},
    qr/belongs to another user/,
);
my $other_kind = HostArtifactsTest::api_request(
    $rpcenv, $TOKEN, 'POST', "$target/stage",
    {
        kind => 'bundle',
        offset => length($archive_bytes),
        data => 'AAAA',
        stage => $archive_stage,
    },
);
$check_match->(
    'a bundle chunk cannot extend an archive stage',
    $other_kind->{message},
    qr/has the kind archive, not bundle/,
);
my $bundle_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $target, 'bundle', "not a bundle\n");

my $install_params = {
    %$install_params_without_stages,
    sha256 => Digest::SHA::sha256_hex($archive_bytes),
    'archive-stage' => $archive_stage,
    'bundle-stage' => $bundle_stage,
};
my $swapped = HostArtifactsTest::api_request(
    $rpcenv, $TOKEN, 'POST', $target,
    { %$install_params, 'archive-stage' => $bundle_stage, 'bundle-stage' => $archive_stage },
);
$check_match->(
    'install rejects swapped stages',
    $swapped->{message},
    qr/has the kind bundle, not archive/,
);
my $before_task = snapshot(@$protected_paths);
my $install_response =
    HostArtifactsTest::api_request($rpcenv, $TOKEN, 'POST', $target, {%$install_params});
$check->(
    'install starts a task',
    $install_response->{status} == 200,
    $install_response->{message},
);
my $task_upid = $install_response->{data};
my ($task_status) = HostArtifactsTest::wait_for_task($task_upid);
$check_match->(
    'the task fails when gh rejects the bundle',
    $task_status,
    qr/gh attestation verify exited with code [1-9]/,
);
$check_match->('the task records the request user', $task_upid, qr/:deploy\@pve!install:\z/);
$check->(
    'a rejected task leaves the files unchanged',
    snapshot(@$protected_paths) eq $before_task,
);
$check_unrelated->('the rejected task');

# An interrupted transaction and the journal restore.

my $many_files = [];
my $many_one = {};
my $many_two = {};
for my $index (1 .. $INTERRUPT_FILE_COUNT) {
    my $path = sprintf('%s/many/file-%04d.conf', $ROOT, $index);
    push @$many_files, { path => $path, mode => '0644', owner => 'root', group => 'root' };
    $many_one->{$path} = { content => "one $index\n" };
    $many_two->{$path} = { content => "two $index\n" };
}
my $many_document = HostArtifactsTest::base_policy('suburban/interrupt', $many_files);
my $many_target = HostArtifactsTest::write_policy($many_document);
my $many_policy = PVE::HostArtifacts::load_policy($many_target);
my $many_archive_one =
    write_artifact('many-one', HostArtifactsTest::artifact($many_document, $many_one));
my $many_archive_two =
    write_artifact('many-two', HostArtifactsTest::artifact($many_document, $many_two));
install_archive($many_policy, $many_archive_one);
my @many_paths = sort keys %$many_one;
my $many_before = content_snapshot(@many_paths);
my $many_journal = "$STATE_DIR/$many_target/journal.json";

my $interrupted = 0;
for my $attempt (1 .. $INTERRUPT_ATTEMPTS) {
    my $changed = interrupt_install($many_policy, $many_archive_two, \@many_paths);
    if (-e $many_journal && $changed > 0 && $changed < scalar(@many_paths)) {
        print "OK: attempt $attempt stopped the install after $changed of"
            . " $INTERRUPT_FILE_COUNT replacements\n";
        $interrupted = 1;
        last;
    }
    print "attempt $attempt did not stop the install between replacements\n";
    PVE::HostArtifacts::with_target_lock(
        $many_target, sub { PVE::HostArtifacts::recover($many_target) },
    );
    install_archive($many_policy, $many_archive_one);
    $many_before = content_snapshot(@many_paths);
}
$check->('the install stopped between two replacements', $interrupted);

my $interrupted_state = get_state($many_target);
$check->('GET reports interrupted', $interrupted_state->{state} eq 'interrupted');
$check->(
    'GET reports the replaced files as changed',
    scalar(grep { !$_->{matches} } @{ $interrupted_state->{files} }) > 0,
);

PVE::HostArtifacts::with_target_lock(
    $many_target, sub { PVE::HostArtifacts::recover($many_target) },
);
$check->(
    'recovery restores every earlier file and inode',
    content_snapshot(@many_paths) eq $many_before,
);
$check->('recovery deletes the journal', !-e $many_journal);
my $recovered_state = get_state($many_target);
$check->('GET reports committed after recovery', $recovered_state->{state} eq 'committed');
$check->(
    'every file matches the earlier record after recovery',
    !grep { !$_->{matches} } @{ $recovered_state->{files} },
);
my @many_leftovers = list_leftovers("$ROOT/many");
$check->('recovery leaves no temporary or backup file', !@many_leftovers, "@many_leftovers");
$check_unrelated->('the interrupted install and its recovery');

# Stage expiry deletes an old stage and keeps an old stage that the journal lists.

$many_document->{programs} = [program_entry('tool')];
HostArtifactsTest::write_policy($many_document);
my $unlisted_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $many_target, 'bundle', "old bundle\n");
my $listed_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $many_target, 'archive', "old archive\n");
my $unlisted_program_stage = stage_program($TOKEN, $many_target, 'program', 'tool', "old\n");
my $listed_program_stage = stage_program($TOKEN, $many_target, 'program', 'tool', "kept\n");
my $listed_program_bundle =
    stage_program($TOKEN, $many_target, 'program-bundle', 'tool', "kept\n");
for my $stage (
    $unlisted_stage, $listed_stage, $unlisted_program_stage, $listed_program_stage,
    $listed_program_bundle,
) {
    my $record_path = stage_record_path($many_target, $stage);
    my $record = $json->decode(HostArtifactsTest::read_file($record_path));
    $record->{created} -= $OLD_STAGE_SECONDS;
    HostArtifactsTest::write_file($record_path, $json->encode($record), 0600);
}
interrupt_install(
    $many_policy,
    $many_archive_two,
    \@many_paths,
    archive_stage => $listed_stage,
    program_stages => [
        {
            name => 'tool',
            archive_stage => $listed_program_stage,
            bundle_stage => $listed_program_bundle,
        },
    ],
);
$check->('the second interruption left a journal', -e $many_journal);
my $new_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $many_target, 'bundle', "new bundle\n");
$check->(
    'a stage call deletes an old stage that the journal does not list',
    !-e stage_record_path($many_target, $unlisted_stage),
);
$check->(
    'a stage call keeps an old stage that the journal lists',
    -e stage_record_path($many_target, $listed_stage),
);
$check->('a stage call keeps a new stage', -e stage_record_path($many_target, $new_stage));
$check->(
    'a stage call deletes an old program stage that the journal does not list',
    !-e stage_record_path($many_target, $unlisted_program_stage),
);
$check->(
    'a stage call keeps the old program stages that the journal lists',
    -e stage_record_path($many_target, $listed_program_stage)
        && -e stage_record_path($many_target, $listed_program_bundle),
);
$check_unrelated->('stage expiry runs');

# The next install restores the interrupted transaction, then commits.
my $resumed_upid = install_archive($many_policy, $many_archive_two);
my $resumed_state = get_state($many_target);
$check->('the next install commits', $resumed_state->{state} eq 'committed');
$check->(
    'the next install writes every file',
    !grep { !$_->{matches} || $_->{write_id} ne $resumed_upid } @{ $resumed_state->{files} },
);
$check_unrelated->('the next install');

# An empty manifest deletes the files of the target.

my $empty_archive = write_artifact('empty', HostArtifactsTest::artifact($many_document, {}));
install_archive($many_policy, $empty_archive);
$check->('an empty manifest deletes the installed files', !grep { -e $_ } @many_paths);
my $empty_state = get_state($many_target);
$check->(
    'an empty manifest leaves an empty installed record',
    $empty_state->{state} eq 'committed' && !@{ $empty_state->{files} },
);
$check_unrelated->('the empty manifest');

sub recover_target {
    my ($policy) = @_;

    PVE::HostArtifacts::with_target_lock(
        $policy->{target}, sub { PVE::HostArtifacts::recover($policy->{target}) },
    );
}

sub journal_of {
    my ($policy) = @_;

    return "$STATE_DIR/$policy->{target}/journal.json";
}

sub numbered_paths {
    my ($dir, $prefix) = @_;

    return [map { sprintf('%s/%s-%04d.conf', $dir, $prefix, $_) } 1 .. $INTERRUPT_FILE_COUNT];
}

# The tests check recovery of an existing directory with a setgid bit.

my $setgid_dir = "$ROOT/setgid";
make_path($setgid_dir, { mode => 0755 });
chmod(02755, $setgid_dir) or die "cannot change the mode of $setgid_dir: $!\n";
my $setgid_paths = numbered_paths($setgid_dir, 'file');
my ($setgid_document, $setgid_policy) = new_target(
    'suburban/setgid',
    file_entries($setgid_paths),
    [{ path => $setgid_dir, mode => '0755', owner => 'root', group => 'root' }],
);
my $setgid_one = write_artifact(
    'setgid-one', HostArtifactsTest::artifact($setgid_document, contents($setgid_paths, 'one')),
);
my $setgid_two = write_artifact(
    'setgid-two', HostArtifactsTest::artifact($setgid_document, contents($setgid_paths, 'two')),
);
my $setgid_journal = journal_of($setgid_policy);
stop_install($setgid_policy, $setgid_one, 'KILL', sub { -e $setgid_journal });
$check->('the killed install leaves a journal', -e $setgid_journal);
eval { recover_target($setgid_policy) };
$check->('recovery accepts the journal mode of a setgid directory', !$@, $@);
$check->('recovery restores the setgid mode', directory_mode($setgid_dir) eq '2755');
$check->('recovery deletes the journal of the setgid directory', !-e $setgid_journal);
$check->('recovery does not leave any new file', !grep { -e $_ } @$setgid_paths);
install_archive($setgid_policy, $setgid_one);
$check->('the next install sets the policy mode', directory_mode($setgid_dir) eq '0755');
$check_unrelated->('the killed install and its recovery');

chmod(02755, $setgid_dir) or die "cannot change the mode of $setgid_dir: $!\n";
my $stopped_error = stop_install($setgid_policy, $setgid_two, 'TERM', sub { -e $setgid_journal });
$check_match->(
    'a stopped install fails with its own error', $stopped_error, qr/\Areceived interrupt\n\z/,
);
$check->('a stopped install restores its files in the same task', !-e $setgid_journal);
$check->(
    'a stopped install restores the setgid mode', directory_mode($setgid_dir) eq '2755',
);
$check->(
    'a stopped install keeps the earlier content',
    count_with_prefix($setgid_paths, 'one') == $INTERRUPT_FILE_COUNT,
);
$check_unrelated->('the stopped install');

# The tests check rollback of new files and a created directory.

my $fresh_dir = "$ROOT/fresh";
my $fresh_paths = numbered_paths($fresh_dir, 'file');
my ($fresh_document, $fresh_policy) = new_target(
    'suburban/fresh',
    file_entries($fresh_paths),
    [{ path => $fresh_dir, mode => '0750', owner => 'root', group => 'root' }],
);
my $fresh_archive = write_artifact(
    'fresh', HostArtifactsTest::artifact($fresh_document, contents($fresh_paths, 'one')),
);
stop_install($fresh_policy, $fresh_archive, 'KILL', sub { -e $fresh_paths->[0] });
my $fresh_present = grep { -e $_ } @$fresh_paths;
$check->(
    'the killed install wrote some but not all new files',
    $fresh_present > 0 && $fresh_present < $INTERRUPT_FILE_COUNT && -e journal_of($fresh_policy),
    "$fresh_present files",
);
recover_target($fresh_policy);
$check->('recovery deletes every new file', !grep { -e $_ } @$fresh_paths);
$check->('recovery deletes the created directory', !-e $fresh_dir);
$check_unrelated->('the rollback of new files');

# The tests check root ownership of the policy file.

my $policy_file = PVE::HostArtifacts::policy_path($target);
my $check_policy_error = sub {
    my ($label, $pattern) = @_;

    my $response = HostArtifactsTest::api_request($rpcenv, $TOKEN, 'GET', $target, {});
    $check_match->($label, $response->{message}, $pattern);
};
chown(1, 1, $policy_file) or die "cannot change the owner of $policy_file: $!\n";
$check_policy_error->('GET rejects a policy file of another owner', qr/must belong to root/);
chown(0, 0, $policy_file) or die "cannot change the owner of $policy_file: $!\n";
chmod(0664, $policy_file) or die "cannot change the mode of $policy_file: $!\n";
$check_policy_error->(
    'GET rejects a group-writable policy file',
    qr/must not be writable by the group or other users/,
);
chmod(0644, $policy_file) or die "cannot change the mode of $policy_file: $!\n";
rename($policy_file, "$policy_file.real") or die "cannot rename $policy_file: $!\n";
symlink("$policy_file.real", $policy_file) or die "cannot link $policy_file: $!\n";
$check_policy_error->('GET rejects a policy file that is a symbolic link', qr/symbolic link/);
unlink($policy_file) or die "cannot delete $policy_file: $!\n";
rename("$policy_file.real", $policy_file) or die "cannot rename $policy_file: $!\n";
$check->('GET accepts the restored policy file', get_state($target)->{state} eq 'committed');

# The tests check root ownership of destination parent directories.

my $parent_dir = "$ROOT/parent/sub";
make_path($parent_dir, { mode => 0755 });
my $parent_file = "$parent_dir/x.conf";
my ($parent_document, $parent_policy) = new_target('suburban/parent', file_entries([$parent_file]));
my $parent_archive = write_artifact(
    'parent',
    HostArtifactsTest::artifact($parent_document, { $parent_file => { content => "x\n" } }),
);
chown(1, 1, $parent_dir) or die "cannot change the owner of $parent_dir: $!\n";
$check_error->(
    'the install rejects a parent directory of another owner',
    sub { install_archive($parent_policy, $parent_archive) },
    qr/parent directory \Q$parent_dir\E of .* must belong to root/,
);
chown(0, 0, $parent_dir) or die "cannot change the owner of $parent_dir: $!\n";
chmod(0775, $parent_dir) or die "cannot change the mode of $parent_dir: $!\n";
$check_error->(
    'the install rejects a group-writable parent directory',
    sub { install_archive($parent_policy, $parent_archive) },
    qr/parent directory \Q$parent_dir\E of .* must not be writable/,
);
$check->('the rejected installs do not leave a file', !-e $parent_file);
chmod(0755, $parent_dir) or die "cannot change the mode of $parent_dir: $!\n";
install_archive($parent_policy, $parent_archive);
$check->('the install succeeds with a root-owned parent directory', -e $parent_file);

# The tests check a policy directory of another owner.

my $owned_dir = "$ROOT/owned";
my $owned_file = "$owned_dir/a.conf";
my ($owned_document, $owned_policy) = new_target(
    'suburban/owned',
    file_entries([$owned_file]),
    [{ path => $owned_dir, mode => '0755', owner => 'daemon', group => 'daemon' }],
);
my $owned_archive = write_artifact(
    'owned',
    HostArtifactsTest::artifact($owned_document, { $owned_file => { content => "a\n" } }),
);
install_archive($owned_policy, $owned_archive);
my @owned_stat = lstat($owned_dir);
$check->(
    'the install creates the directory with the policy owner',
    $owned_stat[4] == scalar(getpwnam('daemon')) && $owned_stat[5] == scalar(getgrnam('daemon')),
);
my $owned_before = snapshot($owned_file);
eval { install_archive($owned_policy, $owned_archive) };
$check->('a repeat install with a directory of another owner succeeds', !$@, $@);
$check->('the repeat install leaves the file unchanged', snapshot($owned_file) eq $owned_before);
$check->(
    'GET reports the file under the directory of another owner as matching',
    files_by_path(get_state($owned_policy->{target}))->{$owned_file}->{matches},
);
$check_unrelated->('the installs with a directory of another owner');

# The tests check stage size limits.

my $limited_document = HostArtifactsTest::base_policy('suburban/limits', []);
$limited_document->{configuration}->{max_archive_bytes} = 100;
$limited_document->{configuration}->{max_bundle_bytes} = 50;
my $limited_target = HostArtifactsTest::write_policy($limited_document);
my $stage_chunk = sub {
    my ($kind, $offset, $bytes, $stage) = @_;

    my $params = { kind => $kind, offset => $offset, data => encode_base64($bytes, '') };
    $params->{stage} = $stage if defined($stage);
    return HostArtifactsTest::api_request(
        $rpcenv, $TOKEN, 'POST', "$limited_target/stage", $params,
    );
};
$check->(
    'an archive stage at the limit succeeds',
    $stage_chunk->('archive', 0, 'a' x 100)->{status} == 200,
);
$check_match->(
    'an archive chunk above the limit fails',
    $stage_chunk->('archive', 0, 'a' x 101)->{message},
    qr/archive is larger than 100 bytes/,
);
my $partial = $stage_chunk->('archive', 0, 'a' x 60)->{data}->{stage};
$check_match->(
    'a later chunk that passes the archive limit fails',
    $stage_chunk->('archive', 60, 'a' x 41, $partial)->{message},
    qr/archive is larger than 100 bytes/,
);
$check->(
    'a bundle stage at the limit succeeds',
    $stage_chunk->('bundle', 0, 'b' x 50)->{status} == 200,
);
$check_match->(
    'a bundle chunk above the limit fails',
    $stage_chunk->('bundle', 0, 'b' x 51)->{message},
    qr/bundle is larger than 50 bytes/,
);

# The tests check validation of program entries in a policy.

my $reserved_dir = "$ROOT/programs/reserved";
my $reserved_file = "$ROOT/programs/reserved.conf";
my $reserved_secret = "$ROOT/programs/reserved.env";
my $program_policy_document = HostArtifactsTest::base_policy(
    'suburban/program-policy',
    file_entries([$reserved_file]),
    [{ path => $reserved_dir, mode => '0755', owner => 'root', group => 'root' }],
);
$program_policy_document->{secret_fields} = [
    {
        name => 'PROGRAM_TOKEN',
        storage_path => $reserved_secret,
        mode => '0600',
        owner => 'root',
        group => 'root',
        pattern => '[a-z]+',
        min_length => 1,
        max_length => 64,
        consumer_units => [],
    },
];
my $without_repository = program_entry('tool');
delete $without_repository->{repository};
my $program_policy_cases = [
    ['a program has an unknown field', [program_entry('tool', extra => 1)], qr/unknown field/],
    ['a program lacks a repository', [$without_repository], qr/'repository' is missing/],
    ['a program name is invalid', [program_entry('Tool')], qr/field 'name'/],
    [
        'a program repository is invalid',
        [program_entry('tool', repository => 'no-owner')],
        qr/field 'repository'/,
    ],
    [
        'a program path is relative',
        [program_entry('tool', path => 'usr/bin/tool')],
        qr/must be an absolute path/,
    ],
    ['a program mode is invalid', [program_entry('tool', mode => '755')], qr/field 'mode'/],
    ['a program owner is invalid', [program_entry('tool', owner => 'Root')], qr/field 'owner'/],
    ['a program group is invalid', [program_entry('tool', group => 'Root')], qr/field 'group'/],
    [
        'a program archive limit is zero',
        [program_entry('tool', max_archive_bytes => 0)],
        qr/'max_archive_bytes' is not a positive integer/,
    ],
    [
        'a program bundle limit is zero',
        [program_entry('tool', max_bundle_bytes => 0)],
        qr/'max_bundle_bytes' is not a positive integer/,
    ],
    [
        'a program name appears more than once',
        [program_entry('tool'), program_entry('tool', path => "$ROOT/programs/other")],
        qr/lists the program tool more than once/,
    ],
    [
        'a program path appears more than once',
        [program_entry('tool'), program_entry('helper', path => "$ROOT/programs/tool")],
        qr/lists the path .* more than once/,
    ],
    [
        'a program path equals a policy file',
        [program_entry('tool', path => $reserved_file)],
        qr/is also a policy file/,
    ],
    [
        'a program path equals a policy directory',
        [program_entry('tool', path => $reserved_dir)],
        qr/is also a policy file/,
    ],
    [
        'a program path equals a secret storage path',
        [program_entry('tool', path => $reserved_secret)],
        qr/is also a policy file/,
    ],
];
for my $case (@$program_policy_cases) {
    my ($label, $programs, $pattern) = @$case;
    my $case_target =
        HostArtifactsTest::write_policy({ %$program_policy_document, programs => $programs });
    $check_error->(
        "policy loading rejects a policy when $label",
        sub { PVE::HostArtifacts::load_policy($case_target) },
        $pattern,
    );
}

# The tests check program stages and the program-stages install parameter.

my $program_document = HostArtifactsTest::base_policy('suburban/program', []);
$program_document->{programs} = [program_entry('tool'), program_entry('helper')];
my $program_target = HostArtifactsTest::write_policy($program_document);
my $other_program_document = HostArtifactsTest::base_policy('suburban/program-other', []);
$other_program_document->{programs} = [program_entry('tool')];
my $other_program_target = HostArtifactsTest::write_policy($other_program_document);

$check_match->(
    'a program stage requires the program parameter',
    program_stage_request($TOKEN, $program_target, 'program', undef, 'a')->{message},
    qr/the kind program requires parameter 'program'/,
);
$check_match->(
    'a program-bundle stage requires the program parameter',
    program_stage_request($TOKEN, $program_target, 'program-bundle', undef, 'a')->{message},
    qr/the kind program-bundle requires parameter 'program'/,
);
for my $kind ('archive', 'bundle') {
    $check_match->(
        "a stage of kind $kind rejects the program parameter",
        program_stage_request($TOKEN, $program_target, $kind, 'tool', 'a')->{message},
        qr/the kind $kind rejects parameter 'program'/,
    );
}
$check_match->(
    'staging rejects a program outside the selected policy',
    program_stage_request($TOKEN, $program_target, 'program', 'missing', 'a')->{message},
    qr/does not list the program missing/,
);
$check_match->(
    'staging rejects a program that only another target policy lists',
    program_stage_request($TOKEN, $other_program_target, 'program', 'helper', 'a')->{message},
    qr/does not list the program helper/,
);
$check_unrelated->('staging rejects invalid program requests');

$check->(
    'a program stage at the size limit in its policy entry succeeds',
    program_stage_request($TOKEN, $program_target, 'program', 'tool', 'a' x 100)->{status} == 200,
);
$check_match->(
    'a program chunk above the size limit in its policy entry fails',
    program_stage_request($TOKEN, $program_target, 'program', 'tool', 'a' x 101)->{message},
    qr/program is larger than 100 bytes/,
);
my $partial_program = stage_program($TOKEN, $program_target, 'program', 'tool', 'a' x 60);
my $program_chunk = sub {
    my ($program) = @_;

    return HostArtifactsTest::api_request(
        $rpcenv, $TOKEN, 'POST', "$program_target/stage",
        {
            kind => 'program',
            offset => 60,
            data => encode_base64('a' x 41, ''),
            stage => $partial_program,
            program => $program,
        },
    );
};
$check_match->(
    'a later chunk that would exceed the program stage size limit fails',
    $program_chunk->('tool')->{message},
    qr/program is larger than 100 bytes/,
);
$check_match->(
    'a later chunk for another program fails',
    $program_chunk->('helper')->{message},
    qr/belongs to another program/,
);
$check->(
    'a program-bundle stage at the size limit in its policy entry succeeds',
    program_stage_request($TOKEN, $program_target, 'program-bundle', 'tool', 'b' x 50)->{status}
        == 200,
);
$check_match->(
    'a program-bundle chunk above the size limit in its policy entry fails',
    program_stage_request($TOKEN, $program_target, 'program-bundle', 'tool', 'b' x 51)->{message},
    qr/program-bundle is larger than 50 bytes/,
);
$check->(
    'an archive stage uses the size limit in the policy configuration',
    program_stage_request($TOKEN, $program_target, 'archive', undef, 'a' x 101)->{status} == 200,
);
$check_unrelated->('staging enforces the program stage size limits');

my $tool_archive = stage_program($TOKEN, $program_target, 'program', 'tool', 'tool');
my $tool_bundle = stage_program($TOKEN, $program_target, 'program-bundle', 'tool', 'bundle');
my $helper_archive = stage_program($TOKEN, $program_target, 'program', 'helper', 'helper');
my $helper_bundle = stage_program($TOKEN, $program_target, 'program-bundle', 'helper', 'bundle');
my $tool_record =
    $json->decode(HostArtifactsTest::read_file(stage_record_path($program_target, $tool_archive)));
$check->(
    'a program stage records the target, actor, kind, and program',
    $tool_record->{target} eq $program_target
        && $tool_record->{user} eq $TOKEN
        && $tool_record->{kind} eq 'program'
        && $tool_record->{program} eq 'tool',
);

my $config_archive =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $program_target, 'archive', 'archive');
my $config_bundle =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $program_target, 'bundle', 'bundle');
my $spare_archive =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $program_target, 'archive', 'spare');
my $other_archive = stage_program($TOKEN, $other_program_target, 'program', 'tool', 'other');
my $other_bundle = stage_program($TOKEN, $other_program_target, 'program-bundle', 'tool', 'other');
my $actor_archive = stage_program('deploy@pve', $program_target, 'program', 'tool', 'actor');
my $actor_bundle = stage_program('deploy@pve', $program_target, 'program-bundle', 'tool', 'actor');

my $program_params = sub {
    my ($program_stages) = @_;

    return {
        %$install_params_without_stages,
        'archive-stage' => $config_archive,
        'bundle-stage' => $config_bundle,
        'program-stages' => $program_stages,
    };
};
my $program_install = sub {
    my ($program_stages) = @_;

    return HostArtifactsTest::api_request(
        $rpcenv, $TOKEN, 'POST', $program_target, $program_params->($program_stages),
    );
};
my $check_program_request = sub {
    my ($label, $program_stages, $pattern) = @_;

    my $response = $program_install->($program_stages);
    $check->("the request does not start a task when $label", $response->{status} != 200);
    $check_match->(
        "the request fails with the expected error when $label",
        $response->{message},
        $pattern,
    );
    $check_unrelated->($label);
};

$check->(
    'a program-stages value in the wrong form does not start a task',
    $program_install->('tool')->{status} == 400,
);
$check_program_request->(
    'the program is unknown', "missing=$tool_archive:$tool_bundle",
    qr/does not list the program missing/,
);
$check_program_request->(
    'a stage belongs to another target', "tool=$other_archive:$other_bundle",
    qr/stage \Q$other_archive\E does not exist for this target/,
);
$check_program_request->(
    'a stage belongs to another actor', "tool=$actor_archive:$actor_bundle",
    qr/stage \Q$actor_archive\E belongs to another user/,
);
$check_program_request->(
    'the request swaps program stages', "tool=$tool_bundle:$tool_archive",
    qr/has the kind program-bundle, not program/,
);
$check_program_request->(
    'the request uses an archive stage in place of a program stage',
    "tool=$spare_archive:$tool_bundle",
    qr/has the kind archive, not program/,
);
$check_program_request->(
    'a stage belongs to another program', "helper=$tool_archive:$tool_bundle",
    qr/stage \Q$tool_archive\E belongs to another program/,
);
$check_program_request->(
    'the request repeats a program',
    "tool=$tool_archive:$tool_bundle,tool=$tool_archive:$tool_bundle",
    qr/lists the program tool more than once/,
);
$check_program_request->(
    'the request repeats a stage',
    "tool=$tool_archive:$tool_bundle,helper=$tool_archive:$helper_bundle",
    qr/references the stage \Q$tool_archive\E more than once/,
);
$check_program_request->(
    'the request also uses the configuration archive stage as a program stage',
    "tool=$config_archive:$tool_bundle",
    qr/references the stage \Q$config_archive\E more than once/,
);

# The tests copy stages from another target into the selected target. Each copied stage record
# retains the original target.
my @copied_stage_paths;
for my $stage ($other_archive, $other_bundle) {
    for my $suffix ('', '.json') {
        my $source = "$STATE_DIR/$other_program_target/stages/$stage$suffix";
        my $copy = "$STATE_DIR/$program_target/stages/$stage$suffix";
        HostArtifactsTest::write_file($copy, HostArtifactsTest::read_file($source), 0600);
        push @copied_stage_paths, $copy;
    }
}
$check_program_request->(
    'a copied stage records another target', "tool=$other_archive:$other_bundle",
    qr/the stage record .* is not valid/,
);
for my $path (@copied_stage_paths) {
    unlink($path) or die "cannot delete $path: $!\n";
}

my $valid_program_stages =
    "tool=$tool_archive:$tool_bundle,helper=$helper_archive:$helper_bundle";
my $checked_request = PVE::HostArtifacts::check_install_request(
    $program_target, $TOKEN, $program_params->($valid_program_stages),
);
$check->(
    'check_install_request returns the parsed program stage references',
    $json->encode($checked_request->{program_stages}) eq $json->encode([
        { name => 'tool', archive_stage => $tool_archive, bundle_stage => $tool_bundle },
        { name => 'helper', archive_stage => $helper_archive, bundle_stage => $helper_bundle },
    ]),
);
my $unreferenced_request = PVE::HostArtifacts::check_install_request(
    $program_target, $TOKEN, $program_params->(undef),
);
$check->(
    'check_install_request returns an empty program stage list when the request omits'
        . ' program-stages',
    !@{ $unreferenced_request->{program_stages} },
);

my $program_task = $program_install->($valid_program_stages);
$check->('a valid program request starts a task', $program_task->{status} == 200);
my ($program_task_status) = HostArtifactsTest::wait_for_task($program_task->{data});
$check_match->(
    'a program request task fails with an error that the host cannot install programs',
    $program_task_status,
    qr/this host cannot install programs yet/,
);
$check->(
    'the failed program task does not write an installed record or a journal',
    !-e "$STATE_DIR/$program_target/installed.json"
        && !-e "$STATE_DIR/$program_target/journal.json",
);
$check->(
    'the failed program task keeps the program stages',
    !grep { !-e stage_record_path($program_target, $_) }
        ($tool_archive, $tool_bundle, $helper_archive, $helper_bundle),
);
$check_unrelated->('the program task fails');

# The tests check installs of one target under the target lock.

my $lock_dir = "$ROOT/lock";
make_path($lock_dir, { mode => 0755 });
my $lock_paths = [map { "$lock_dir/file-$_.conf" } 1 .. 50];
my ($lock_document, $lock_policy) = new_target('suburban/lock', file_entries($lock_paths));
my $lock_one = write_artifact(
    'lock-one', HostArtifactsTest::artifact($lock_document, contents($lock_paths, 'one')),
);
my $lock_two = write_artifact(
    'lock-two', HostArtifactsTest::artifact($lock_document, contents($lock_paths, 'two')),
);

# The function takes the target lock in a child process for $seconds and returns the process ID
# after the child has the lock.
sub hold_lock {
    my ($policy, $seconds) = @_;

    pipe(my $reader, my $writer) or die "cannot create a pipe: $!\n";
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        close($reader);
        PVE::HostArtifacts::with_target_lock(
            $policy->{target},
            sub {
                print {$writer} "locked\n";
                close($writer);
                Time::HiRes::sleep($seconds);
            },
        );
        POSIX::_exit(0);
    }
    close($writer);
    my $line = <$reader>;
    close($reader);
    die "the lock holder did not take the lock\n" if ($line // '') ne "locked\n";
    return $pid;
}

my $short_holder = hold_lock($lock_policy, 3);
my $wait_start = Time::HiRes::time();
install_archive($lock_policy, $lock_one);
my $waited = Time::HiRes::time() - $wait_start;
waitpid($short_holder, 0);
$check->('an install waits for the target lock', $waited >= 2.5, "waited $waited seconds");

my $long_holder = hold_lock($lock_policy, 30);
my $lock_before = snapshot(@$lock_paths);
$check_error->(
    'an install fails when the target lock stays taken',
    sub { install_archive($lock_policy, $lock_two) },
    qr/can't lock file/,
);
$check->('the failed install leaves the files unchanged', snapshot(@$lock_paths) eq $lock_before);
kill('KILL', $long_holder);
waitpid($long_holder, 0);

my @installers;
for my $archive ($lock_two, $lock_one) {
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        open(STDOUT, '>', '/dev/null') or POSIX::_exit(2);
        eval { install_archive($lock_policy, $archive) };
        POSIX::_exit($@ ? 1 : 0);
    }
    push @installers, $pid;
}
my @exit_codes;
for my $pid (@installers) {
    waitpid($pid, 0);
    push @exit_codes, $? >> 8;
}
$check->('two concurrent installs of one target both succeed', "@exit_codes" eq '0 0');
my $one_count = count_with_prefix($lock_paths, 'one');
my $two_count = count_with_prefix($lock_paths, 'two');
$check->(
    'the files equal one complete archive after concurrent installs',
    ($one_count == 50 && $two_count == 0) || ($one_count == 0 && $two_count == 50),
    "one=$one_count two=$two_count",
);
my $lock_state = get_state($lock_policy->{target});
$check->(
    'GET reports every file as matching after concurrent installs',
    $lock_state->{state} eq 'committed' && !grep { !$_->{matches} } @{ $lock_state->{files} },
);
$check_unrelated->('the concurrent installs');

# The tests check two targets that share an inspect-only parent directory.

my $shared_dir = "$ROOT/shared";
make_path($shared_dir, { mode => 0700 });
chmod(0700, $shared_dir) or die "cannot change the mode of $shared_dir: $!\n";
my $shared_parent = [{ path => $shared_dir, mode => '0755', owner => 'root', group => 'root' }];
my $shared_b_paths = numbered_paths($shared_dir, 'b');
my $shared_a_file = "$shared_dir/a.conf";
my ($shared_b_document, $shared_b_policy) =
    new_target('suburban/shared-b', file_entries($shared_b_paths), [], $shared_parent);
my $shared_b_archive = write_artifact(
    'shared-b', HostArtifactsTest::artifact($shared_b_document, contents($shared_b_paths, 'b')),
);
my $shared_a_files = { $shared_a_file => { content => "a\n" } };
my ($shared_a_document, $shared_a_policy) =
    new_target('suburban/shared-a', file_entries([$shared_a_file]), [], $shared_parent);
my $shared_a_archive =
    write_artifact('shared-a', HostArtifactsTest::artifact($shared_a_document, $shared_a_files));

$check_error->(
    'the install fails when the inspect-only parent has another mode',
    sub { install_archive($shared_b_policy, $shared_b_archive) },
    qr/inspect-only parent directory \Q$shared_dir\E has mode 0700/,
);
$check->(
    'the failed install does not write a file or a journal',
    (!grep { -e $_ } @$shared_b_paths) && !-e journal_of($shared_b_policy),
);
$check->(
    'the failed install leaves the parent mode unchanged',
    directory_mode($shared_dir) eq '0700',
);
chmod(0755, $shared_dir) or die "cannot change the mode of $shared_dir: $!\n";
chown(1, 1, $shared_dir) or die "cannot change the owner of $shared_dir: $!\n";
$check_error->(
    'the install fails when the inspect-only parent has another owner',
    sub { install_archive($shared_b_policy, $shared_b_archive) },
    qr/inspect-only parent directory \Q$shared_dir\E has mode 0755, owner 1/,
);
$check->(
    'the failed install leaves the parent owner unchanged',
    (lstat($shared_dir))[4] == 1 && !-e journal_of($shared_b_policy),
);
chown(0, 0, $shared_dir) or die "cannot change the owner of $shared_dir: $!\n";

# The host owner sets the parent directory to the mode that both policies require.
stop_install($shared_b_policy, $shared_b_archive, 'KILL', sub { -e $shared_b_paths->[0] });
$check->('the install of target B stops with a journal', -e journal_of($shared_b_policy));
install_archive($shared_a_policy, $shared_a_archive);
my $shared_committed = $json->encode([(lstat($shared_dir))[2, 4, 5]]);
my $shared_a_committed = snapshot($shared_a_file);
recover_target($shared_b_policy);
$check->(
    'the recovery of target B leaves the parent of the committed target A unchanged',
    $json->encode([(lstat($shared_dir))[2, 4, 5]]) eq $shared_committed
        && directory_mode($shared_dir) eq '0755',
);
$check->('the recovery of target B deletes its new files', !grep { -e $_ } @$shared_b_paths);
$check->(
    'the recovery of target B leaves the file of target A unchanged',
    snapshot($shared_a_file) eq $shared_a_committed,
);
my $shared_a_state = get_state($shared_a_policy->{target});
$check->(
    'GET reports every file of target A as matching',
    $shared_a_state->{state} eq 'committed'
        && !grep { !$_->{matches} } @{ $shared_a_state->{files} },
);
$check_unrelated->('the recovery of target B');

# The install rejects a manifest directory that the policy lists only as an inspect-only parent.
my $listed_document = { %$shared_a_document, directories => $shared_parent };
my $listed_archive = write_artifact(
    'shared-listed',
    HostArtifactsTest::artifact($listed_document, { $shared_a_file => { content => "a two\n" } }),
);
my $listed_state = sub {
    return $json->encode({
        parent => [(lstat($shared_dir))[1, 2, 4, 5, 10]],
        file => snapshot($shared_a_file),
        target => HostArtifactsTest::target_state($shared_a_policy->{target}, $shared_a_file),
    });
};
my $listed_before = $listed_state->();
$check_error->(
    'the install rejects a manifest directory that the policy lists as inspect-only',
    sub { install_archive($shared_a_policy, $listed_archive) },
    qr/manifest lists the directory \Q$shared_dir\E, and the policy lists it only as an/,
);
$check->(
    'the rejection does not change the parent, the file, the installed record, the journal,'
        . ' or the lock file',
    $listed_state->() eq $listed_before && !-e journal_of($shared_a_policy),
);
$check_unrelated->('the rejected manifest directory');

# The policy lists an inspect-only parent without mode, owner, and group.
my $plain_dir = "$ROOT/plain";
make_path($plain_dir, { mode => 0755 });
chmod(0775, $plain_dir) or die "cannot change the mode of $plain_dir: $!\n";
my $plain_file = "$plain_dir/p.conf";
my ($plain_document, $plain_policy) =
    new_target('suburban/plain', file_entries([$plain_file]), [], [{ path => $plain_dir }]);
my $plain_archive = write_artifact(
    'plain', HostArtifactsTest::artifact($plain_document, { $plain_file => { content => "p\n" } }),
);
$check_error->(
    'the install fails when the group can write to the inspect-only parent',
    sub { install_archive($plain_policy, $plain_archive) },
    qr/the group or other users can write to the inspect-only parent directory \Q$plain_dir\E\n/,
);
$check->('the failed install does not write the file', !-e $plain_file);
chmod(0755, $plain_dir) or die "cannot change the mode of $plain_dir: $!\n";
install_archive($plain_policy, $plain_archive);
$check->('the install succeeds when root owns the inspect-only parent', -e $plain_file);

# The recovery of an owned directory restores the change of the same target.
my $owned_c_dir = "$ROOT/owned-c";
make_path($owned_c_dir, { mode => 0700 });
chmod(0700, $owned_c_dir) or die "cannot change the mode of $owned_c_dir: $!\n";
my $owned_c_paths = numbered_paths($owned_c_dir, 'c');
my ($owned_c_document, $owned_c_policy) = new_target(
    'suburban/owned-c',
    file_entries($owned_c_paths),
    [{ path => $owned_c_dir, mode => '0750', owner => 'root', group => 'root' }],
);
my $owned_c_archive = write_artifact(
    'owned-c', HostArtifactsTest::artifact($owned_c_document, contents($owned_c_paths, 'c')),
);
stop_install($owned_c_policy, $owned_c_archive, 'KILL', sub { -e $owned_c_paths->[0] });
$check->(
    'the install of an owned directory stops with the new mode',
    -e journal_of($owned_c_policy) && directory_mode($owned_c_dir) eq '0750',
);
recover_target($owned_c_policy);
$check->(
    'the recovery restores the mode of the owned directory',
    directory_mode($owned_c_dir) eq '0700',
);
$check_unrelated->('the owned directory recovery');

# A policy cannot list one path as an owned directory and as an inspect-only parent.
my $overlap_document = HostArtifactsTest::base_policy(
    'suburban/overlap',
    [],
    [{ path => $plain_dir, mode => '0755', owner => 'root', group => 'root' }],
);
$overlap_document->{parent_directories} = [{ path => $plain_dir }];
my $overlap_target = HostArtifactsTest::write_policy($overlap_document);
$check_error->(
    'policy loading rejects a path in directories and in parent_directories',
    sub { PVE::HostArtifacts::load_policy($overlap_target) },
    qr/in directories and in parent_directories/,
);

# The stopped target keeps its journal and uses that journal to restore its files.

recover_target({ target => $stopped_target });
$check->(
    'the stopped target restores its files from its own journal',
    !-e "$STATE_DIR/$stopped_target/journal.json" && !grep { -e $_ } @$stopped_paths,
);

remove_tree($ROOT, $WORK);
print "all tests passed\n";

exit(0);
