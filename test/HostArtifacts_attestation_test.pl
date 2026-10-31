#!/usr/bin/perl -T

# The test runs the installed /usr/bin/gh with the host artifact module against a real attested
# release asset. HOST_ARTIFACT_FIXTURE_DIR must contain configsctl_linux_amd64.tar.gz from the
# configsctl release 202610300043-29-7976a64, its bundle from gh attestation download as
# configsctl_linux_amd64.tar.gz.sigstore.jsonl, and trusted_root.jsonl from
# gh attestation trusted-root. The test writes below /etc/pve-overlay, /var/lib/pve-overlay,
# and /srv and must run as root in a disposable container.

use strict;
use warnings;

use lib qw(.. .);

use Digest::SHA;
use File::Path qw(make_path remove_tree);

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

my $fixture_dir = $ENV{HOST_ARTIFACT_FIXTURE_DIR};
die "set HOST_ARTIFACT_FIXTURE_DIR to the directory with the attested configsctl fixture\n"
    if !defined($fixture_dir) || $fixture_dir !~ m{\A(/[^\0]+)\z};
$fixture_dir = $1;
delete @ENV{qw(PATH IFS CDPATH ENV BASH_ENV)};

HostArtifactsTest::require_disposable_root();
my $check = \&HostArtifactsTest::check;
my $check_error = \&HostArtifactsTest::check_error;

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
eval { PVE::HostArtifacts::verify_attestation($policy, $request, $archive, $bundle) };
$check->('gh accepts the authentic archive with the policy identity', !$@, $@);

my $appended = "$WORK/appended.tar.gz";
HostArtifactsTest::write_file($appended, $archive_bytes . "\0");
$check_error->(
    'gh rejects the archive with one appended byte',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $policy,
            { %$request, sha256 => Digest::SHA::sha256_hex($archive_bytes . "\0") },
            $appended,
            $bundle,
        );
    },
    qr/gh attestation verify exited with code [1-9]/,
);

my $wrong_workflow_policy =
    fixture_policy('attestation/wrong-workflow', workflow_uri => $WRONG_WORKFLOW);
$check_error->(
    'gh rejects another workflow identity',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $wrong_workflow_policy, $request, $archive, $bundle,
        );
    },
    qr/gh attestation verify exited with code [1-9]/,
);

my $wrong_ref_policy = fixture_policy('attestation/wrong-ref', source_ref => $WRONG_REF);
$check_error->(
    'gh rejects another source ref',
    sub {
        PVE::HostArtifacts::verify_attestation($wrong_ref_policy, $request, $archive, $bundle);
    },
    qr/gh attestation verify exited with code [1-9]/,
);

$check_error->(
    'the subject check rejects another asset name',
    sub {
        PVE::HostArtifacts::verify_attestation(
            $policy, { %$request, asset => 'configsctl_linux_arm64.tar.gz' }, $archive, $bundle,
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

remove_tree($WORK);
print "all tests passed\n";

exit(0);
