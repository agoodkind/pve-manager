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
my $unrelated_target = PVE::HostArtifacts::target_of_workspace('suburban/unrelated');
HostArtifactsTest::write_file(
    PVE::HostArtifacts::policy_path($unrelated_target), "this is not JSON\n",
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

# Identity and member rejections. Every rejection leaves the files unchanged.

my $protected_paths = [@all_paths, $installed_path];

sub check_rejected {
    my ($label, $archive_path, $pattern, %request_override) = @_;

    my $before = snapshot(@$protected_paths);
    $check_error->(
        $label, sub { install_archive($policy, $archive_path, %request_override) }, $pattern,
    );
    $check->("$label leaves the files unchanged", snapshot(@$protected_paths) eq $before);
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

# Stage expiry deletes an old stage and keeps an old stage that the journal lists.

my $unlisted_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $many_target, 'bundle', "old bundle\n");
my $listed_stage =
    HostArtifactsTest::stage_file($rpcenv, $TOKEN, $many_target, 'archive', "old archive\n");
for my $stage ($unlisted_stage, $listed_stage) {
    my $record_path = stage_record_path($many_target, $stage);
    my $record = $json->decode(HostArtifactsTest::read_file($record_path));
    $record->{created} -= $OLD_STAGE_SECONDS;
    HostArtifactsTest::write_file($record_path, $json->encode($record), 0600);
}
interrupt_install(
    $many_policy, $many_archive_two, \@many_paths, archive_stage => $listed_stage,
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

# The next install restores the interrupted transaction, then commits.
my $resumed_upid = install_archive($many_policy, $many_archive_two);
my $resumed_state = get_state($many_target);
$check->('the next install commits', $resumed_state->{state} eq 'committed');
$check->(
    'the next install writes every file',
    !grep { !$_->{matches} || $_->{write_id} ne $resumed_upid } @{ $resumed_state->{files} },
);

# An empty manifest deletes the files of the target.

my $empty_archive = write_artifact('empty', HostArtifactsTest::artifact($many_document, {}));
install_archive($many_policy, $empty_archive);
$check->('an empty manifest deletes the installed files', !grep { -e $_ } @many_paths);
my $empty_state = get_state($many_target);
$check->(
    'an empty manifest leaves an empty installed record',
    $empty_state->{state} eq 'committed' && !@{ $empty_state->{files} },
);

remove_tree($ROOT, $WORK);
print "all tests passed\n";

exit(0);
