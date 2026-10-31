package HostArtifactsTest;

use strict;
use warnings;

use Digest::SHA;
use File::Path qw(make_path remove_tree);
use IO::Compress::Gzip qw(gzip $GzipError);
use JSON;
use MIME::Base64 qw(encode_base64);
use POSIX qw();
use Time::HiRes qw();

use PVE::API2;
use PVE::HTTPServer;
use PVE::HostArtifacts;
use PVE::INotify;
use PVE::ProcFSTools;
use PVE::Tools;

my $TARGET_POLICY_DIR = '/etc/pve-overlay/host-artifacts/targets';
my $STATE_DIR = '/var/lib/pve-overlay/host-artifacts';
my $TASK_DIR = '/var/log/pve/tasks';
my $CHUNK_BYTES = 96 * 1024;
my $TASK_TIMEOUT_SECONDS = 300;
my $TAR_BLOCK_BYTES = 512;
my $INTERRUPT_FILE_COUNT = 300;
my $INTERRUPT_TIMEOUT_SECONDS = 120;

my $json = JSON->new->utf8->canonical;

sub json {
    return $json;
}

sub require_disposable_root {
    die "this test writes below /etc and /var/lib and must run as root in a disposable"
        . " container\n"
        if $> != 0;
    make_path($TARGET_POLICY_DIR, $TASK_DIR, { mode => 0755 });
    use_emulated_start_time();
}

# fork_worker compares the start time that the parent reads for the worker with the start time
# that the worker reads for itself. Under the emulation of the amd64 test image on another
# architecture, a process reads a different start time for itself. In that case the test uses
# a constant start time, as exec-concurrency-test.pl in pve-container does.
sub use_emulated_start_time {
    pipe(my $result_reader, my $result_writer) or die "cannot create a pipe: $!\n";
    pipe(my $done_reader, my $done_writer) or die "cannot create a pipe: $!\n";
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        close($result_reader);
        close($done_writer);
        print {$result_writer} PVE::ProcFSTools::read_proc_starttime($$) // '';
        close($result_writer);
        # The child exits after the parent has read its start time.
        my $done = <$done_reader>;
        POSIX::_exit(0);
    }
    close($result_writer);
    close($done_reader);
    my $child_view = do { local $/ = undef; <$result_reader> } // '';
    my $parent_view = PVE::ProcFSTools::read_proc_starttime($pid) // '';
    close($result_reader);
    close($done_writer);
    waitpid($pid, 0);
    return if $parent_view eq $child_view;

    print "the process start time differs between the parent and the child, and the test uses"
        . " a constant start time\n";
    no warnings 'redefine';
    *PVE::ProcFSTools::read_proc_starttime = sub { return 1 };
}

sub write_file {
    my ($path, $content, $mode) = @_;

    open(my $handle, '>', $path) or die "cannot write $path: $!\n";
    binmode($handle);
    print {$handle} $content;
    close($handle) or die "cannot write $path: $!\n";
    chmod($mode // 0644, $path) or die "cannot change the mode of $path: $!\n";
}

sub read_file {
    my ($path) = @_;

    open(my $handle, '<', $path) or die "cannot read $path: $!\n";
    binmode($handle);
    local $/ = undef;
    my $content = <$handle>;
    close($handle);
    return $content;
}

# Writes the policy of one target and returns the target. The target is the SHA-256 of the
# workspace selector unless $target is given.
sub write_policy {
    my ($policy, $target) = @_;

    $target //= PVE::HostArtifacts::target_of_workspace($policy->{workspace});
    write_file("$TARGET_POLICY_DIR/$target.json", $json->encode($policy));
    return $target;
}

sub base_policy {
    my ($workspace, $files, $directories) = @_;

    return {
        workspace => $workspace,
        node => PVE::INotify::nodename(),
        environment => 'testbed',
        configuration => {
            repository => 'agoodkind/configs',
            workflow_uri => 'https://github.com/agoodkind/configs/.github/workflows/ci.yml'
                . '@refs/heads/main',
            source_ref => 'refs/heads/main',
            max_archive_bytes => 64 * 1024 * 1024,
            max_bundle_bytes => 1024 * 1024,
        },
        directories => $directories // [],
        files => $files,
    };
}

sub tar_header {
    my ($member) = @_;

    my $header = pack(
        'a100 a8 a8 a8 a12 a12 a8 a1 a100 a6 a2 a32 a32 a8 a8 a155 a12',
        $member->{name},
        sprintf('%07o', $member->{mode} // 0644),
        sprintf('%07o', 0),
        sprintf('%07o', 0),
        sprintf('%011o', length($member->{content} // '')),
        sprintf('%011o', 0),
        ' ' x 8,
        $member->{type} // '0',
        $member->{linkname} // '',
        "ustar\0",
        '00',
        '',
        '',
        '',
        '',
        '',
        '',
    );
    my $checksum = unpack('%32C*', $header);
    substr($header, 148, 8) = sprintf('%06o', $checksum) . "\0 ";
    return $header;
}

# Writes a gzip ustar archive with the members in list order. Each member has name, content,
# and optional mode, type, and linkname.
sub write_archive {
    my ($path, $members) = @_;

    my $tar = '';
    for my $member (@$members) {
        my $content = $member->{content} // '';
        $tar .= tar_header($member) . $content;
        $tar .= "\0" x ((-length($content)) % $TAR_BLOCK_BYTES);
    }
    $tar .= "\0" x (2 * $TAR_BLOCK_BYTES);
    gzip(\$tar => $path) or die "cannot write $path: $GzipError\n";
}

# Builds the manifest and members of an artifact. $files maps each path to content, mode,
# owner, and group.
sub artifact {
    my ($policy, $files, %override) = @_;

    my $manifest = {
        schema_version => 1,
        repository => $policy->{configuration}->{repository},
        source_revision => $override{source_revision} // ('a' x 40),
        workspace => $policy->{workspace},
        node => $policy->{node},
        environment => $policy->{environment},
        directories => $policy->{directories},
        files => [],
    };
    my $members = [];
    for my $path (sort keys %$files) {
        my $file = $files->{$path};
        my $member = 'files' . $path;
        push @{ $manifest->{files} }, {
            member => $member,
            path => $path,
            size => length($file->{content}),
            sha256 => Digest::SHA::sha256_hex($file->{content}),
            mode => $file->{mode} // '0644',
            owner => $file->{owner} // 'root',
            group => $file->{group} // 'root',
        };
        push @$members, { name => $member, content => $file->{content} };
    }
    return ($manifest, $members);
}

sub request {
    my ($archive_path, %override) = @_;

    return {
        release_tag => 'hostconfig-test-202610300000-1-aaaaaaa',
        asset => 'hostconfig_test.tar.gz',
        sha256 => Digest::SHA->new(256)->addfile($archive_path)->hexdigest(),
        source_revision => 'a' x 40,
        archive_stage => '0' x 32,
        bundle_stage => '1' x 32,
        %override,
    };
}

sub api_request {
    my ($rpcenv, $user, $method, $path, $params) = @_;

    my $server = bless({ rpcenv => $rpcenv }, 'PVE::HTTPServer');
    my $auth = { userid => $user };
    $auth->{api_token} = 1 if $user =~ m/!/;
    return $server->rest_handler(
        '127.0.0.1', $method, "/nodes/localhost/host-artifacts/$path", $auth, $params,
    );
}

sub stage_file {
    my ($rpcenv, $user, $target, $kind, $content) = @_;

    my $stage;
    my $offset = 0;
    while (1) {
        my $chunk = substr($content, $offset, $CHUNK_BYTES);
        my $params = { kind => $kind, offset => $offset, data => encode_base64($chunk, '') };
        $params->{stage} = $stage if defined($stage);
        my $response = api_request($rpcenv, $user, 'POST', "$target/stage", $params);
        die "staging failed with status $response->{status}: "
            . ($response->{message} // '') . "\n"
            if $response->{status} != 200;
        $stage = $response->{data}->{stage};
        $offset += length($chunk);
        die "the stage length is $response->{data}->{length}, not $offset\n"
            if $response->{data}->{length} != $offset;
        last if $offset >= length($content);
    }
    return $stage;
}

# The function waits until the task of the UPID exits and returns its status line and log.
sub wait_for_task {
    my ($upid) = @_;

    my ($task, $log_path) = PVE::Tools::upid_decode($upid);
    my $deadline = time() + $TASK_TIMEOUT_SECONDS;
    # The start time in the UPID can be the constant of use_emulated_start_time.
    while (PVE::ProcFSTools::check_process_running($task->{pid})) {
        die "task $upid did not exit within $TASK_TIMEOUT_SECONDS seconds\n"
            if time() > $deadline;
        Time::HiRes::sleep(0.1);
    }
    return (PVE::Tools::upid_read_status($upid), read_file($log_path));
}

sub check {
    my ($label, $condition, $detail) = @_;

    die "FAILED: $label" . (defined($detail) ? ": $detail" : '') . "\n" if !$condition;
    print "OK: $label\n";
}

# The function returns the content and metadata of the listed files and of the installed record,
# secret record, journal, and lock file of one target. A test compares the result before and
# after a request for another target.
sub target_state {
    my ($target, @paths) = @_;

    my $state_dir = "$STATE_DIR/$target";
    my $state = {};
    for my $path (
        @paths,
        "$state_dir/installed.json",
        "$state_dir/secrets.json",
        "$state_dir/journal.json",
        "/run/lock/pve-overlay-host-artifact-$target.lck",
    ) {
        my @stat = lstat($path);
        if (!@stat) {
            $state->{$path} = 'absent';
            next;
        }
        my $digest = -f _ ? Digest::SHA->new(256)->addfile($path)->hexdigest() : '';
        $state->{$path} = join(':', $digest, @stat[1, 2, 4, 5, 7, 9]);
    }
    return $json->encode($state);
}

# The function creates a target with many files and starts its install in a child process. It
# kills the child after the first file appears, and the target keeps its journal. The function
# returns the target and the file paths.
sub interrupted_target {
    my ($workspace, $dir) = @_;

    make_path($dir, { mode => 0755 });
    my $paths = [map { sprintf('%s/file-%04d.conf', $dir, $_) } 1 .. $INTERRUPT_FILE_COUNT];
    my $document = base_policy(
        $workspace,
        [map { { path => $_, mode => '0644', owner => 'root', group => 'root' } } @$paths],
    );
    my $target = write_policy($document);
    remove_tree("$STATE_DIR/$target");
    my $policy = PVE::HostArtifacts::load_policy($target);
    my ($manifest, $members) =
        artifact($document, { map { $_ => { content => "$_\n" } } @$paths });
    my $archive = "$dir.tar.gz";
    write_archive(
        $archive, [{ name => 'manifest.json', content => $json->encode($manifest) }, @$members],
    );
    my $request = request($archive);

    my $pid = fork() // die "the process cannot fork: $!\n";
    if (!$pid) {
        open(STDOUT, '>', '/dev/null') or POSIX::_exit(2);
        eval {
            PVE::HostArtifacts::with_target_lock(
                $target,
                sub {
                    PVE::HostArtifacts::install_verified_archive(
                        $policy, $request, $archive, 'UPID:test:interrupted', 'deploy@pve!install',
                    );
                },
            );
        };
        POSIX::_exit($@ ? 1 : 0);
    }
    my $deadline = Time::HiRes::time() + $INTERRUPT_TIMEOUT_SECONDS;
    while (!-e $paths->[0]) {
        last if Time::HiRes::time() > $deadline;
        last if waitpid($pid, POSIX::WNOHANG()) == $pid;
        Time::HiRes::sleep(0.0005);
    }
    kill('KILL', $pid);
    waitpid($pid, 0);
    die "the stopped install of $workspace does not have a journal\n"
        if !-e "$STATE_DIR/$target/journal.json";
    return ($target, $paths);
}

sub check_match {
    my ($label, $value, $pattern) = @_;

    $value //= '';
    die "FAILED: $label: '$value' does not match $pattern\n" if $value !~ $pattern;
    print "OK: $label\n";
}

sub check_error {
    my ($label, $code, $pattern) = @_;

    eval { $code->() };
    my $error = $@ // '';
    die "FAILED: $label: the call succeeded\n" if $error eq '';
    die "FAILED: $label: the error '$error' does not match $pattern\n" if $error !~ $pattern;
    chomp($error);
    print "OK: $label: $error\n";
}

1;
