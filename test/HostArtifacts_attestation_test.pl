#!/usr/bin/perl -T

# The test runs the installed /usr/bin/gh with the host artifact module against real attested
# release assets. HOST_ARTIFACT_FIXTURE_DIR must contain configsctl_linux_amd64.tar.gz from the
# configsctl release 202610300043-29-7976a64, opnsensectl_linux_amd64.tar.gz from the opnsensectl
# release 202609190337-7-7db20fb, and mwan_linux_amd64.tar.gz from the mwan release
# 202610291257-ff-c09e62f. Each archive needs its bundle from gh attestation download as
# <asset>.sigstore.jsonl, and the directory needs trusted_root.jsonl from
# gh attestation trusted-root. The test writes below /etc/pve-overlay, /var/lib/pve-overlay,
# and /srv and must run as root in a disposable container without network access.

use strict;
use warnings;

use lib qw(.. .);

use Digest::SHA;
use File::Path qw(make_path remove_tree);
use MIME::Base64 qw(encode_base64);
use POSIX qw();
use Time::HiRes qw();

use PVE::HostArtifacts;
use PVE::RPCEnvironment;

use HostArtifactsTest;

my $FIXTURE_ASSET = 'configsctl_linux_amd64.tar.gz';
my $FIXTURE_SHA256 = '032e903daaca614d32fa354965eafa5a13d78ad040cac88ba90f91e1b127dfc9';
my $FIXTURE_REVISION = '7976a64a4c3944c6e179daa6e0f6607a3328328b';
my $FIXTURE_SIGNER_DIGEST = '4e9b31f5b944594bb74e316aefa49093b5abd865';
my $FIXTURE_REPOSITORY = 'agoodkind/configsctl';
my $FIXTURE_WORKFLOW =
    'https://github.com/agoodkind/go-makefile/.github/workflows/_package.yml@refs/heads/main';
my $WRONG_WORKFLOW =
    'https://github.com/agoodkind/configsctl/.github/workflows/release.yml@refs/heads/main';
my $FIXTURE_REF = 'refs/heads/main';
my $WRONG_REF = 'refs/heads/other';
my $WORK = '/srv/host-artifacts-attestation-work';
my $TOKEN = 'deploy@pve!install';
my $STATE_DIR = '/var/lib/pve-overlay/host-artifacts';
my $CHUNK_BYTES = 96 * 1024;
my $PROGRAM_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024;
my $PROGRAM_MAX_BUNDLE_BYTES = 1024 * 1024;
my $INTERRUPT_FILE_COUNT = 300;
my $INTERRUPT_ATTEMPTS = 5;
my $INTERRUPT_TIMEOUT_SECONDS = 120;
my $POLL_SECONDS = 0.0005;
my $NETWORK_DEVICE_DIR = '/sys/class/net';
my $DEVICE_UP_FLAG = 0x1;
my $GH_REJECTS = qr/gh attestation verify exited with code [1-9]/;
my $WANCONFIG_ASSET = 'wanconfig-stack_linux_amd64.tar.gz';
my $WANCONFIG_SHA256 = '60bf467c9601f612785e2d6fb6f973258fd94af05311e89df87deacf72e1b0c8';
my $INSTALLED_PROGRAM_FIELDS =
    [qw(repository release_tag asset sha256 source_revision signer_revision)];
my $PROGRAMS = {
    mwan => {
        repository => 'agoodkind/mwan',
        release_tag => '202610291257-ff-c09e62f',
        asset => 'mwan_linux_amd64.tar.gz',
        sha256 => '46f00098244c808dbf5bad67890632b36deda47fa6c5a1f463c75fb4f436b94d',
        source_revision => 'c09e62f7e0d61526c91183734bf28c6934accded',
        signer_revision => '4e9b31f5b944594bb74e316aefa49093b5abd865',
        member => 'mwan',
        member_sha256 => 'bde87a6f73fd6ff6e91fafb4793a639c96bc993ece132569079fd85637bcf279',
    },
    opnsensectl => {
        repository => 'agoodkind/opnsensectl',
        release_tag => '202609190337-7-7db20fb',
        asset => 'opnsensectl_linux_amd64.tar.gz',
        sha256 => '29e65cb0cc7b7924478416ab98d7c22e8d3e1679e7cbcfdbff42323fde874399',
        source_revision => '7db20fb56fa01fa41bbb9ebeb03f29c281bce24a',
        signer_revision => '6f29e0969c7c302aee9c1a23b3424c91f8c7796d',
        member => 'opnsensectl',
        member_sha256 => '19153b0b2026c69df0c2f7c9b0268dcdb3c85c7313544ba993e7587fb048322e',
    },
};
my @PROGRAM_NAMES = sort keys %$PROGRAMS;

my $fixture_dir = $ENV{HOST_ARTIFACT_FIXTURE_DIR};
die "set HOST_ARTIFACT_FIXTURE_DIR to the directory with the attested configsctl fixture\n"
    if !defined($fixture_dir) || $fixture_dir !~ m{\A(/[^\0]+)\z};
$fixture_dir = $1;
delete @ENV{qw(PATH IFS CDPATH ENV BASH_ENV)};

HostArtifactsTest::require_disposable_root();
my $check = \&HostArtifactsTest::check;
my $check_error = \&HostArtifactsTest::check_error;
my $check_match = \&HostArtifactsTest::check_match;
my $json = HostArtifactsTest::json();

# The rollback and the new install count as offline evidence only when every device other than
# lo is down and does not have a route.
sub require_no_network {
    my @active;
    for my $device (@{ directory_names($NETWORK_DEVICE_DIR) }) {
        my $flags_path = "$NETWORK_DEVICE_DIR/$device/flags";
        next if $device eq 'lo' || !-e $flags_path;
        my $flags = HostArtifactsTest::read_file($flags_path);
        chomp($flags);
        push @active, $device if hex($flags) & $DEVICE_UP_FLAG;
    }
    die "this test needs a container without network access, and these devices are up:"
        . " @active\n"
        if @active;

    my @routes = split(m/\n/, HostArtifactsTest::read_file('/proc/net/route'));
    shift @routes;
    my @devices = map { (split(' ', $_))[0] } @routes;
    if (-e '/proc/net/ipv6_route') {
        my @routes_v6 = split(m/\n/, HostArtifactsTest::read_file('/proc/net/ipv6_route'));
        push @devices, map { (split(' ', $_))[-1] } @routes_v6;
    }
    my @routed = grep { $_ ne 'lo' } @devices;
    die "this test needs a container without network access, and these devices have routes:"
        . " @routed\n"
        if @routed;
}
require_no_network();

my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'host-artifacts-test.cfg');

remove_tree($WORK);
make_path($WORK, { mode => 0755 });
my $archive = "$fixture_dir/$FIXTURE_ASSET";
my $bundle = "$fixture_dir/$FIXTURE_ASSET.sigstore.jsonl";
HostArtifactsTest::write_file(
    PVE::HostArtifacts::trusted_root_path(),
    HostArtifactsTest::read_file("$fixture_dir/trusted_root.jsonl"),
);
my $archive_bytes = HostArtifactsTest::read_file($archive);
$check->(
    'the fixture has the release SHA-256',
    Digest::SHA::sha256_hex($archive_bytes) eq $FIXTURE_SHA256,
);

sub fixture_policy {
    my ($workspace, %configuration) = @_;

    my $document = HostArtifactsTest::base_policy($workspace, []);
    $document->{configuration} = {
        repository => $FIXTURE_REPOSITORY,
        workflow_uri => $FIXTURE_WORKFLOW,
        source_ref => $FIXTURE_REF,
        signer_digest => $FIXTURE_SIGNER_DIGEST,
        max_archive_bytes => 8 * 1024 * 1024,
        max_bundle_bytes => 1024 * 1024,
        %configuration,
    };
    my $target = HostArtifactsTest::write_policy($document);
    return PVE::HostArtifacts::load_policy($target);
}

my $request = {
    release_tag => '202610300043-29-7976a64',
    asset => $FIXTURE_ASSET,
    sha256 => $FIXTURE_SHA256,
    source_revision => $FIXTURE_REVISION,
};

my $policy = fixture_policy('attestation/fixture');
my $configuration = $policy->{configuration};
eval { PVE::HostArtifacts::verify_attestation($configuration, $request, $archive, $bundle) };
$check->('gh accepts the authentic archive with the policy identity', !$@, $@);

my $appended = "$WORK/appended.tar.gz";
HostArtifactsTest::write_file($appended, $archive_bytes . "\0");
$check_error->(
    'gh rejects the archive with one appended byte',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $configuration,
            { %$request, sha256 => Digest::SHA::sha256_hex($archive_bytes . "\0") },
            $appended,
            $bundle,
        );
    },
    $GH_REJECTS,
);

my $wrong_workflow_policy =
    fixture_policy('attestation/wrong-workflow', workflow_uri => $WRONG_WORKFLOW);
$check_error->(
    'gh rejects another workflow identity',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $wrong_workflow_policy->{configuration}, $request, $archive, $bundle,
        );
    },
    $GH_REJECTS,
);

my $wrong_ref_policy = fixture_policy('attestation/wrong-ref', source_ref => $WRONG_REF);
$check_error->(
    'gh rejects another source ref',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $wrong_ref_policy->{configuration}, $request, $archive, $bundle,
        );
    },
    $GH_REJECTS,
);

$check_error->(
    'the subject check rejects another asset name',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $configuration,
            { %$request, asset => 'configsctl_linux_arm64.tar.gz' },
            $archive,
            $bundle,
        );
    },
    qr/does not have the subject configsctl_linux_arm64\.tar\.gz/,
);

# The install task runs gh before it reads the manifest. The fixture is a configsctl release
# archive without a host artifact manifest. The task accepts the attestation and then fails
# the archive check.
my $archive_stage = HostArtifactsTest::stage_file(
    $rpcenv, $TOKEN, $policy->{target}, 'archive', $archive_bytes,
);
my $bundle_stage = HostArtifactsTest::stage_file(
    $rpcenv, $TOKEN, $policy->{target}, 'bundle', HostArtifactsTest::read_file($bundle),
);
my $response = HostArtifactsTest::api_request(
    $rpcenv,
    $TOKEN,
    'POST',
    $policy->{target},
    {
        'release-tag' => $request->{release_tag},
        asset => $FIXTURE_ASSET,
        sha256 => $FIXTURE_SHA256,
        'source-revision' => $FIXTURE_REVISION,
        'archive-stage' => $archive_stage,
        'bundle-stage' => $bundle_stage,
    },
);
$check->(
    'install starts a task for the fixture',
    $response->{status} == 200,
    $response->{message},
);
my ($status, $log) = HostArtifactsTest::wait_for_task($response->{data});
HostArtifactsTest::check_match(
    'the install task accepts the attestation before it reads the archive',
    $log,
    qr/gh attestation verify accepted \Q$FIXTURE_ASSET\E/,
);
$check->(
    'the install task rejects the fixture in the archive check',
    scalar($status ne 'OK' && $status !~ m/gh attestation verify/),
    $status,
);
print "the install task ended with: $status\n";

# The tests install the retained opnsensectl and mwan archives. The fixture directory does not
# contain an attested schema 2 configuration archive. The tests call install_verified_archive,
# which runs gh for every program archive.

my $program_bytes = {};
my $bundle_bytes = {};
for my $name (@PROGRAM_NAMES) {
    my $asset = $PROGRAMS->{$name}->{asset};
    $program_bytes->{$name} = HostArtifactsTest::read_file("$fixture_dir/$asset");
    $bundle_bytes->{$name} = HostArtifactsTest::read_file("$fixture_dir/$asset.sigstore.jsonl");
    $check->(
        "the $name fixture has the release SHA-256",
        Digest::SHA::sha256_hex($program_bytes->{$name}) eq $PROGRAMS->{$name}->{sha256},
    );
}

my $program_dir = "$WORK/bin";
my $file_dir = "$WORK/etc";
make_path($program_dir, $file_dir, { mode => 0755 });
my $file_paths = [];
for my $index (1 .. $INTERRUPT_FILE_COUNT) {
    push @$file_paths, sprintf('%s/file-%04d.conf', $file_dir, $index);
}
my $program_paths = [map { "$program_dir/$_" } @PROGRAM_NAMES];

sub program_entry {
    my ($name) = @_;

    return {
        name => $name,
        repository => $PROGRAMS->{$name}->{repository},
        workflow_uri => $FIXTURE_WORKFLOW,
        source_ref => $FIXTURE_REF,
        path => "$program_dir/$name",
        mode => '0755',
        owner => 'root',
        group => 'root',
        max_archive_bytes => $PROGRAM_MAX_ARCHIVE_BYTES,
        max_bundle_bytes => $PROGRAM_MAX_BUNDLE_BYTES,
    };
}

my $program_document = HostArtifactsTest::base_policy(
    'attestation/programs',
    [map { { path => $_, mode => '0644', owner => 'root', group => 'root' } } @$file_paths],
);
$program_document->{programs} = [map { program_entry($_) } @PROGRAM_NAMES];
my $program_target = HostArtifactsTest::write_policy($program_document);
my $program_policy = PVE::HostArtifacts::load_policy($program_target);
my $journal_path = "$STATE_DIR/$program_target/journal.json";

# The function returns the selected policy with one changed program entry and restores the valid
# policy file.
sub policy_with {
    my ($name, %override) = @_;

    my $document = $json->decode($json->encode($program_document));
    my ($entry) = grep { $_->{name} eq $name } @{ $document->{programs} };
    %$entry = (%$entry, %override);
    HostArtifactsTest::write_policy($document);
    my $changed = PVE::HostArtifacts::load_policy($program_target);
    HostArtifactsTest::write_policy($program_document);
    return $changed;
}

sub program_identity {
    my ($name, %override) = @_;

    return {
        %{ $program_policy->{programs}->{$name} },
        signer_digest => $PROGRAMS->{$name}->{signer_revision},
        %override,
    };
}

sub verify_program {
    my ($identity, $program_request, $name) = @_;

    my $asset = $PROGRAMS->{$name}->{asset};
    PVE::HostArtifacts::verify_attestation(
        $identity, $program_request, "$fixture_dir/$asset", "$fixture_dir/$asset.sigstore.jsonl",
    );
}

for my $name (@PROGRAM_NAMES) {
    eval { verify_program(program_identity($name), $PROGRAMS->{$name}, $name) };
    $check->("gh accepts the $name archive with its own signer revision", !$@, $@);
}
$check_error->(
    'gh rejects the opnsensectl archive with the signer revision of mwan',
    sub {
        my $identity = program_identity(
            'opnsensectl', signer_digest => $PROGRAMS->{mwan}->{signer_revision},
        );
        verify_program($identity, $PROGRAMS->{opnsensectl}, 'opnsensectl');
    },
    $GH_REJECTS,
);
$check_error->(
    'gh rejects the mwan archive with the signer revision of opnsensectl',
    sub {
        my $identity = program_identity(
            'mwan', signer_digest => $PROGRAMS->{opnsensectl}->{signer_revision},
        );
        verify_program($identity, $PROGRAMS->{mwan}, 'mwan');
    },
    $GH_REJECTS,
);
$check_error->(
    'the subject check rejects the digest of the second subject under the mwan asset name',
    sub {
        my $changed_request = { %{ $PROGRAMS->{mwan} }, sha256 => $WANCONFIG_SHA256 };
        verify_program(program_identity('mwan'), $changed_request, 'mwan');
    },
    qr/does not have the subject mwan_linux_amd64\.tar\.gz/,
);
$check_error->(
    'the subject check rejects the mwan digest under the asset name of the second subject',
    sub {
        my $changed_request = { %{ $PROGRAMS->{mwan} }, asset => $WANCONFIG_ASSET };
        verify_program(program_identity('mwan'), $changed_request, 'mwan');
    },
    qr/does not have the subject \Q$WANCONFIG_ASSET\E/,
);

# The unrelated target has a committed install and a secret record. The stopped target keeps its
# journal. The tests compare both targets after each step.

my $unrelated_dir = "$WORK/unrelated";
make_path($unrelated_dir, { mode => 0755 });
my $unrelated_file = "$unrelated_dir/u.conf";
my $unrelated_secret = "$unrelated_dir/secret.env";
my $unrelated_document = HostArtifactsTest::base_policy(
    'attestation/unrelated',
    [{ path => $unrelated_file, mode => '0644', owner => 'root', group => 'root' }],
);
$unrelated_document->{secret_fields} = [
    {
        name => 'UNRELATED_TOKEN',
        storage_path => $unrelated_secret,
        mode => '0600',
        owner => 'root',
        group => 'root',
        pattern => '[a-z]+',
        min_length => 1,
        max_length => 64,
        consumer_units => [],
    },
];
my $unrelated_target = HostArtifactsTest::write_policy($unrelated_document);
my $unrelated_policy = PVE::HostArtifacts::load_policy($unrelated_target);
my ($unrelated_manifest, $unrelated_members) = HostArtifactsTest::artifact(
    $unrelated_document, { $unrelated_file => { content => "u\n" } },
);
my $unrelated_archive = "$WORK/unrelated.tar.gz";
my $unrelated_manifest_member =
    { name => 'manifest.json', content => $json->encode($unrelated_manifest) };
HostArtifactsTest::write_archive(
    $unrelated_archive, [$unrelated_manifest_member, @$unrelated_members],
);
PVE::HostArtifacts::with_target_lock(
    $unrelated_target,
    sub {
        PVE::HostArtifacts::install_verified_archive(
            $unrelated_policy,
            HostArtifactsTest::request($unrelated_archive),
            $unrelated_archive,
            'UPID:attestation:unrelated',
            $TOKEN,
        );
    },
);
PVE::HostArtifacts::set_secret(
    $unrelated_target, 'UNRELATED_TOKEN', 'unrelated', 1, 'UPID:attestation:secret',
);
my ($stopped_target, $stopped_paths) =
    HostArtifactsTest::interrupted_target('attestation/stopped', "$WORK/stopped");

sub unrelated_state {
    return $json->encode([
        HostArtifactsTest::target_state(
            $unrelated_target, $unrelated_dir, $unrelated_file, $unrelated_secret,
        ),
        HostArtifactsTest::target_state($stopped_target, @$stopped_paths),
    ]);
}
my $unrelated_before = unrelated_state();

sub check_unrelated {
    my ($label) = @_;

    $check->(
        "the files, records, journals, and lock files of the unrelated targets stay unchanged"
            . " after $label",
        unrelated_state() eq $unrelated_before,
    );
}

sub directory_names {
    my ($dir) = @_;

    opendir(my $handle, $dir) or die "cannot read $dir: $!\n";
    my @names = sort grep { $_ ne '.' && $_ ne '..' } readdir($handle);
    closedir($handle);
    return \@names;
}

# The state includes each target file, every name in the two directories, and the installed
# record, secret record, journal, and lock file of the selected target.
sub program_state {
    return $json->encode([
        HostArtifactsTest::target_state($program_target, @$program_paths, @$file_paths),
        directory_names($program_dir),
        directory_names($file_dir),
    ]);
}

sub stage_program {
    my ($kind, $name, $content) = @_;

    my $stage;
    my $offset = 0;
    while (1) {
        my $chunk = substr($content, $offset, $CHUNK_BYTES);
        my $params = {
            kind => $kind,
            program => $name,
            offset => $offset,
            data => encode_base64($chunk, ''),
        };
        $params->{stage} = $stage if defined($stage);
        my $response = HostArtifactsTest::api_request(
            $rpcenv, $TOKEN, 'POST', "$program_target/stage", $params,
        );
        die "staging $name failed with status $response->{status}: "
            . ($response->{message} // '') . "\n"
            if $response->{status} != 200;
        $stage = $response->{data}->{stage};
        $offset += length($chunk);
        last if $offset >= length($content);
    }
    return $stage;
}

sub stage_programs {
    my $references = [];
    for my $name (@PROGRAM_NAMES) {
        push @$references, {
            name => $name,
            archive_stage => stage_program('program', $name, $program_bytes->{$name}),
            bundle_stage => stage_program('program-bundle', $name, $bundle_bytes->{$name}),
        };
    }
    return $references;
}

sub manifest_program {
    my ($name) = @_;

    return {
        %{ $PROGRAMS->{$name} },
        name => $name,
        path => "$program_dir/$name",
        mode => '0755',
        owner => 'root',
        group => 'root',
    };
}

sub change_program {
    my ($name, %override) = @_;

    return sub {
        my ($manifest) = @_;
        my ($program) = grep { $_->{name} eq $name } @{ $manifest->{programs} };
        %$program = (%$program, %override);
    };
}

# The function writes a schema 2 archive with one file for each path in $file_paths and manifest
# entries for the two retained programs. Each file starts with $prefix.
sub configuration_archive {
    my ($name, $prefix, $change) = @_;

    my ($manifest, $members) = HostArtifactsTest::artifact(
        $program_document, { map { $_ => { content => "$prefix $_\n" } } @$file_paths },
    );
    $manifest->{schema_version} = 2;
    $manifest->{programs} = [map { manifest_program($_) } @PROGRAM_NAMES];
    $change->($manifest) if $change;
    my $path = "$WORK/$name.tar.gz";
    HostArtifactsTest::write_archive(
        $path, [{ name => 'manifest.json', content => $json->encode($manifest) }, @$members],
    );
    return $path;
}

sub install_programs {
    my ($selected_policy, $archive_path, $references) = @_;

    my $install_request = HostArtifactsTest::request($archive_path, program_stages => $references);
    PVE::HostArtifacts::with_target_lock(
        $selected_policy->{target},
        sub {
            PVE::HostArtifacts::install_verified_archive(
                $selected_policy, $install_request, $archive_path, "UPID:attestation:$$", $TOKEN,
            );
        },
    );
}

# The function runs an install in a child process and returns its exit code and output.
sub logged_install {
    my ($archive_path, $references) = @_;

    my $log_path = "$WORK/install.log";
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        open(STDOUT, '>', $log_path) or POSIX::_exit(2);
        $| = 1;
        eval { install_programs($program_policy, $archive_path, $references) };
        my $error = $@;
        print "the install failed: $error" if $error;
        POSIX::_exit($error ? 1 : 0);
    }
    waitpid($pid, 0);
    return ($? >> 8, HostArtifactsTest::read_file($log_path));
}

sub check_verified_before_write {
    my ($label, $log) = @_;

    my $first_write = index($log, "\nwrote ");
    $check->("$label writes a file", $first_write >= 0, $log);
    for my $name (@PROGRAM_NAMES) {
        my ($asset, $sha256) = @{ $PROGRAMS->{$name} }{qw(asset sha256)};
        my $accepted = index($log, "gh attestation verify accepted $asset with SHA-256 $sha256\n");
        $check->(
            "$label verifies the $name archive with gh before it writes a file",
            $accepted >= 0 && $accepted < $first_write,
            $log,
        );
    }
}

sub check_stages_removed {
    my ($label, $references) = @_;

    for my $reference (@$references) {
        for my $stage (@$reference{qw(archive_stage bundle_stage)}) {
            my $stage_path = "$STATE_DIR/$program_target/stages/$stage";
            $check->(
                "$label removes the stage $stage of the program $reference->{name}",
                !-e $stage_path && !-e "$stage_path.json",
            );
        }
    }
}

sub check_installed_programs {
    my ($label) = @_;

    for my $name (@PROGRAM_NAMES) {
        my $path = "$program_dir/$name";
        my @stat = lstat($path);
        $check->(
            "$label installs the executable member of $name with the policy metadata",
            Digest::SHA->new(256)->addfile($path)->hexdigest()
                eq $PROGRAMS->{$name}->{member_sha256}
                && sprintf('%04o', $stat[2] & 07777) eq '0755'
                && $stat[4] == 0
                && $stat[5] == 0,
        );
    }
    $check->("$label does not install README.md", !-e "$program_dir/README.md");

    my $response =
        HostArtifactsTest::api_request($rpcenv, $TOKEN, 'GET', $program_target, {});
    $check->("GET succeeds after $label", $response->{status} == 200, $response->{message});
    my $state = $response->{data};
    $check->("GET reports the committed state after $label", $state->{state} eq 'committed');
    $check->(
        "GET reports that every file matches after $label",
        !grep { !$_->{matches} } @{ $state->{files} },
    );
    my $expected = [];
    for my $name (@PROGRAM_NAMES) {
        my $fields = { map { $_ => $PROGRAMS->{$name}->{$_} } @$INSTALLED_PROGRAM_FIELDS };
        push @$expected, { %$fields, name => $name };
    }
    $check->(
        "GET lists the installed programs after $label",
        $json->encode($state->{installed}->{programs}) eq $json->encode($expected),
    );
}

sub write_previous_programs {
    for my $path (@$program_paths) {
        HostArtifactsTest::write_file($path, "previous $path\n", 0755);
    }
}

sub stop_during_replacement {
    my ($archive_path, $references) = @_;

    my $first_path = $program_paths->[0];
    my $first_inode = (lstat($first_path))[1];
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        open(STDOUT, '>', '/dev/null') or POSIX::_exit(2);
        eval { install_programs($program_policy, $archive_path, $references) };
        POSIX::_exit($@ ? 1 : 0);
    }
    my $deadline = Time::HiRes::time() + $INTERRUPT_TIMEOUT_SECONDS;
    while (Time::HiRes::time() < $deadline) {
        my $inode = (lstat($first_path))[1] // $first_inode;
        last if $inode != $first_inode;
        last if waitpid($pid, POSIX::WNOHANG()) == $pid;
        Time::HiRes::sleep($POLL_SECONDS);
    }
    kill('KILL', $pid);
    waitpid($pid, 0);
}

write_previous_programs();
my $program_stages = stage_programs();
my $valid_archive = configuration_archive('programs-one', 'one');

sub check_rejected {
    my ($label, $selected_policy, $archive_path, $references, $pattern) = @_;

    my $before = program_state();
    $check_error->(
        $label, sub { install_programs($selected_policy, $archive_path, $references) }, $pattern,
    );
    $check->("$label does not write a target file", program_state() eq $before);
    check_unrelated($label);
}

check_rejected(
    'another program repository',
    policy_with('opnsensectl', repository => 'agoodkind/mwan'),
    configuration_archive(
        'wrong-repository', 'one', change_program('opnsensectl', repository => 'agoodkind/mwan'),
    ),
    $program_stages,
    $GH_REJECTS,
);
check_rejected(
    'another program workflow',
    policy_with('mwan', workflow_uri => $WRONG_WORKFLOW),
    $valid_archive,
    $program_stages,
    $GH_REJECTS,
);
check_rejected(
    'another program source revision',
    $program_policy,
    configuration_archive(
        'wrong-source', 'one', change_program('mwan', source_revision => 'b' x 40),
    ),
    $program_stages,
    $GH_REJECTS,
);
check_rejected(
    'another program signer revision',
    $program_policy,
    configuration_archive(
        'wrong-signer',
        'one',
        change_program(
            'opnsensectl', signer_revision => $PROGRAMS->{mwan}->{signer_revision},
        ),
    ),
    $program_stages,
    $GH_REJECTS,
);

my $changed_bytes = $program_bytes->{opnsensectl} . "\0";
my $changed_stage = stage_program('program', 'opnsensectl', $changed_bytes);
my $changed_stages = [
    $program_stages->[0],
    { %{ $program_stages->[1] }, archive_stage => $changed_stage },
];
check_rejected(
    'changed program archive bytes',
    $program_policy,
    configuration_archive(
        'wrong-bytes',
        'one',
        change_program('opnsensectl', sha256 => Digest::SHA::sha256_hex($changed_bytes)),
    ),
    $changed_stages,
    $GH_REJECTS,
);
check_rejected(
    'a manifest SHA-256 that differs from the staged archive SHA-256',
    $program_policy,
    configuration_archive(
        'wrong-archive', 'one', change_program('opnsensectl', sha256 => 'c' x 64),
    ),
    $program_stages,
    qr/does not have the subject opnsensectl_linux_amd64\.tar\.gz/,
);
check_rejected(
    'another member SHA-256',
    $program_policy,
    configuration_archive(
        'wrong-member', 'one', change_program('opnsensectl', member_sha256 => 'c' x 64),
    ),
    $program_stages,
    qr/member 'opnsensectl' of the program opnsensectl has SHA-256 [0-9a-f]{64}/,
);
check_rejected(
    'an absent member',
    $program_policy,
    configuration_archive(
        'absent-member', 'one', change_program('opnsensectl', member => 'missing'),
    ),
    $program_stages,
    qr/does not contain the member 'missing'/,
);
check_rejected(
    'another program destination',
    $program_policy,
    configuration_archive(
        'wrong-destination', 'one', change_program('opnsensectl', path => "$program_dir/other"),
    ),
    $program_stages,
    qr/program opnsensectl does not match the path, mode, owner, and group in the policy/,
);
check_rejected(
    'a program destination that equals a target file path',
    $program_policy,
    configuration_archive(
        'collision', 'one', change_program('opnsensectl', path => $file_paths->[0]),
    ),
    $program_stages,
    qr/matches a file path or a secret storage path of this target/,
);

my ($install_exit_code, $install_log) = logged_install($valid_archive, $program_stages);
$check->('the install of both programs succeeds', $install_exit_code == 0, $install_log);
check_verified_before_write('the install', $install_log);
check_stages_removed('the install', $program_stages);
check_installed_programs('the install');
check_unrelated('the install of both programs');

# The test stops an install during replacement. The first program has already changed.

my $second_archive = configuration_archive('programs-two', 'two');
my $interrupted_stages;
my $before_interrupt;
my $first_program_sha256;
my $interrupted = 0;
for my $attempt (1 .. $INTERRUPT_ATTEMPTS) {
    write_previous_programs();
    for my $path (@$file_paths) {
        HostArtifactsTest::write_file($path, "one $path\n");
    }
    $before_interrupt = program_state();
    $first_program_sha256 = Digest::SHA->new(256)->addfile($program_paths->[0])->hexdigest();
    $interrupted_stages = stage_programs();
    stop_during_replacement($second_archive, $interrupted_stages);
    my $phase = '';
    if (-e $journal_path) {
        $phase = $json->decode(HostArtifactsTest::read_file($journal_path))->{phase};
    }
    if ($phase eq 'replacing') {
        print "OK: attempt $attempt stopped the install during replacement\n";
        $interrupted = 1;
        last;
    }
    print "attempt $attempt did not stop the install during replacement\n";
    PVE::HostArtifacts::with_target_lock(
        $program_target, sub { PVE::HostArtifacts::recover($program_target) },
    );
}
$check->('the kill stopped the install during replacement', $interrupted);
$check->(
    'the stopped install replaced the first program file before the kill',
    Digest::SHA->new(256)->addfile($program_paths->[0])->hexdigest() ne $first_program_sha256,
);
$check->(
    'the journal lists the program stages of the stopped install',
    $json->encode($json->decode(HostArtifactsTest::read_file($journal_path))->{program_stages})
        eq $json->encode($interrupted_stages),
);
check_unrelated('the stopped install');

# The next task restores the journal backups, and gh then exits with failure because the mwan
# bundle does not attest the configuration archive. This run provides only rollback evidence.

my $second_bytes = HostArtifactsTest::read_file($second_archive);
my $rollback_response = HostArtifactsTest::api_request(
    $rpcenv,
    $TOKEN,
    'POST',
    $program_target,
    {
        'release-tag' => 'hostconfig-test-202610300000-1-aaaaaaa',
        asset => 'hostconfig_test.tar.gz',
        sha256 => Digest::SHA::sha256_hex($second_bytes),
        'source-revision' => 'a' x 40,
        'archive-stage' => HostArtifactsTest::stage_file(
            $rpcenv, $TOKEN, $program_target, 'archive', $second_bytes,
        ),
        'bundle-stage' => HostArtifactsTest::stage_file(
            $rpcenv, $TOKEN, $program_target, 'bundle', $bundle_bytes->{mwan},
        ),
        'program-stages' => join(
            ',',
            map { "$_->{name}=$_->{archive_stage}:$_->{bundle_stage}" } @$interrupted_stages,
        ),
    },
);
$check->(
    'the task after the kill starts',
    $rollback_response->{status} == 200,
    $rollback_response->{message},
);
my (undef, $rollback_log) = HostArtifactsTest::wait_for_task($rollback_response->{data});
$check_match->('gh exits with failure in the rollback task', $rollback_log, $GH_REJECTS);
$check_match->(
    'the rollback task restores the journal backups before gh runs',
    $rollback_log,
    qr/restoring the files of the interrupted transaction/,
);
$check->(
    'gh does not accept an archive in the rollback task',
    $rollback_log !~ m/gh attestation verify accepted/,
    $rollback_log,
);
$check->(
    'the rollback restores the content, metadata, and names of every target file',
    program_state() eq $before_interrupt,
);
$check->('the rollback deletes the journal', !-e $journal_path);
check_unrelated('the rollback');
print "the rollback task ended with a gh failure, and it counts only as rollback evidence\n";

# A new install verifies every retained program archive before it writes a file.

my ($new_exit_code, $new_log) = logged_install($second_archive, $interrupted_stages);
$check->('the new install after the rollback succeeds', $new_exit_code == 0, $new_log);
check_verified_before_write('the new install', $new_log);
check_stages_removed('the new install', $interrupted_stages);
check_installed_programs('the new install');
$check->(
    'the new install writes the second configuration',
    !grep { HostArtifactsTest::read_file($_) ne "two $_\n" } @$file_paths,
);
check_unrelated('the new install');

remove_tree($WORK);
print "all tests passed\n";

exit(0);
