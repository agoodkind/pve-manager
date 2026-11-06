#!/usr/bin/env perl

use strict;
use warnings;

use Digest::SHA qw(sha256_hex);
use File::Copy qw(copy);
use File::Path qw(make_path);
use File::Temp qw(tempdir);
use FindBin;
use Test::More;

use lib $FindBin::Bin;
use HostArtifactsInstalledSourceTest;

my ($configsctl, $tofu) = @ARGV;
die "usage: $0 /absolute/path/to/configsctl /absolute/path/to/tofu\n"
    unless @ARGV == 2 && $configsctl =~ m{\A/} && $tofu =~ m{\A/}
    && -x $configsctl && -x $tofu;
umask(0077);
my $private = tempdir('installed-source-runlog-XXXXXXXX', TMPDIR => 1, CLEANUP => 1);
END {
    chdir($FindBin::Bin) or die "cannot leave the temporary fixture before cleanup: $!\n";
}
make_path(map { "$private/$_" } qw(tmp bin data native workspaces/sample
    ansible/inventory/group_vars/all home/.config/ansible));
for my $pair (
    ['installed-source-runlog/configsctl.yml', 'configsctl.yml'],
    ['installed-source-runlog/main.tf', 'workspaces/sample/main.tf'],
    ['installed-source-runlog/native.tf', 'native/main.tf'],
    ['installed-source-seed.vault', 'ansible/inventory/group_vars/all/vault.yml'],
    ['installed-source-seed.pass', 'home/.config/ansible/vault.pass'],
) {
    copy("$FindBin::Bin/$pair->[0]", "$private/$pair->[1]") or die "cannot copy fixture: $!\n";
    chmod(0600, "$private/$pair->[1]") == 1 or die "cannot restrict fixture: $!\n";
}
symlink($tofu, "$private/bin/tofu") or die "cannot link the real OpenTofu executable: $!\n";
chdir($private) or die "cannot enter the private fixture: $!\n";
local %ENV = (HOME => "$private/home", PATH => "$private/bin:/usr/bin:/bin",
    TMPDIR => "$private/tmp", TF_DATA_DIR => "$private/data", TF_IN_AUTOMATION => '1');
my $token = HostArtifactsInstalledSourceTest::random_token();
my $password;
{
    open(my $file, '<', "$private/home/.config/ansible/vault.pass") or die "cannot read seed: $!\n";
    local $/;
    $password = <$file>;
    close($file) or die "cannot close seed: $!\n";
    chomp($password);
}
my @credentials = ($password, $token);
my $logs = {};

sub invoke {
    my ($input, $expected, @arguments) = @_;
    my ($code, $streams) = HostArtifactsInstalledSourceTest::capture_command(
        $private, \@credentials, $input, $configsctl, @arguments);
    my $output = join("\n", @$streams);
    is($code, $expected, "configsctl @arguments exits with $expected") or die $output;
    my $new;
    ($logs, $new) = HostArtifactsInstalledSourceTest::check_run_logs(
        "$private/tmp", $logs, $output, \@credentials);
    return ($output, $new);
}

invoke("vault_installed_source_token: '$token'\n", 0, 'set-secrets');
my (undef, $init) = invoke('', 0, 'tofu', 'sample', 'init', '-input=false', '-no-color');
ok(scalar(grep { m{/tofu-init-} } keys %$init), 'successful init retains its private diagnostic log');
is(scalar(keys %$init), 3, 'init and native configuration retain three checked logs');
$ENV{TF_VAR_expected_token_sha256} = sha256_hex("wrong-$token");
my ($output, $plan) = invoke('', 1, 'tofu', 'sample', 'plan', '-input=false', '-no-color');
my $diagnostic = 'The supplied token must match the expected SHA-256 digest.';
ok(index($output, $diagnostic) < 0, 'the failed plan does not print its validation diagnostic');
my @failed = grep { m{/tofu-plan-} && index($plan->{$_}, $diagnostic) >= 0 } keys %$plan;
is(scalar(@failed), 1, 'the new failed plan log contains the validation diagnostic');
HostArtifactsInstalledSourceTest::require_log_diagnostic($plan, 'plan', $diagnostic);
eval { HostArtifactsInstalledSourceTest::require_log_diagnostic($init, 'plan', $diagnostic); };
like($@, qr/the new plan logs did not report/, 'older logs cannot satisfy the failed plan diagnostic');
is(scalar(keys %$plan), 4, 'the failed plan scans only its four new native logs');
is(scalar(keys %$logs), 7, 'both invocations preserve all seven diagnostic logs');

my $rejected = "$private/rejected";
make_path("$rejected/configsctl-installed-leftover");
eval { HostArtifactsInstalledSourceTest::check_run_logs($rejected, {}, '', \@credentials); };
like($@, qr/unexpected temporary execution files/, 'an execution copy still fails cleanup');
my $leaked = "$private/leaked/configs-runs";
make_path($leaked);
my ($name) = $failed[0] =~ m{/([^/]+)\z};
copy($failed[0], "$leaked/$name") or die "cannot copy the real plan log: $!\n";
open(my $file, '>>', "$leaked/$name") or die "cannot append the private test credential: $!\n";
print {$file} $token or die "cannot write the private test credential: $!\n";
close($file) or die "cannot close the copied log: $!\n";
eval { HostArtifactsInstalledSourceTest::check_run_logs("$private/leaked", {}, '', \@credentials); };
like($@, qr/run log exposed a fixture credential/, 'the scanner rejects a credential in a copied real log');

my $current = { directory => $private, credentials => \@credentials, run_logs => $logs };
my $other = { directory => "$private/other", credentials => [], run_logs => {} };
make_path("$other->{directory}/tmp");
HostArtifactsInstalledSourceTest::command($other, '', 0, undef, $configsctl, 'version');
is(scalar(keys %{$other->{run_logs}}), 0, 'an independent version command does not inherit earlier logs');
is(scalar(keys %{$current->{run_logs}}), 7, 'the first context retains its seven logs after another context runs');
eval { HostArtifactsInstalledSourceTest::assert_private($current, $token, 'the first context'); };
like($@, qr/exposed a fixture credential/, 'the first context still rejects its own credential');
eval { HostArtifactsInstalledSourceTest::assert_private($other, $token, 'the other context'); };
is($@, '', 'an independent context does not inherit another context credential');
HostArtifactsInstalledSourceTest::command($current, '', 0, undef, $configsctl, 'version');
is(scalar(keys %{$current->{run_logs}}), 7, 'the first context resumes with its own retained log map');
done_testing();
