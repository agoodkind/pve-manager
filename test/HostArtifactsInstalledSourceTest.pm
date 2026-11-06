package HostArtifactsInstalledSourceTest;

use strict;
use warnings;

use Archive::Tar;
use Digest::SHA qw(sha256_hex);
use File::Find qw(find);
use File::Path qw(make_path);
use File::Temp qw(tempfile);
use IPC::Open3;
use IO::Uncompress::Unzip qw($UnzipError);

my $workspace = 'suburban/hostartifact-acceptance';
my $root = '/srv/hostartifact-acceptance';
my $private = '/var/lib/configsctl-acceptance';
my $password_file = '/root/.config/ansible/vault.pass';
my $vault = "$root/ansible/inventory/group_vars/all/vault.yml";
my $module = "$root/workspaces/sample/host/main.tf";
my $target = sha256_hex($workspace);

sub assert_private {
    my ($context, $content, $label) = @_;
    for my $value (@{$context->{credentials}}) {
        die "$label exposed a fixture credential\n" if index($content, $value) >= 0;
    }
}

sub read_json {
    my ($context, $path) = @_;
    return $context->{json}->decode(HostArtifactsTest::read_file($path));
}

sub digest {
    return Digest::SHA->new(256)->addfile($_[0])->hexdigest;
}

sub check_run_logs {
    my ($temporary, $previous, $output, $credentials) = @_;
    opendir(my $temporary_dir, $temporary)
        or die "cannot inspect temporary execution files: $!\n";
    my @left = grep { $_ ne '.' && $_ ne '..' } readdir($temporary_dir);
    closedir($temporary_dir) or die "cannot close temporary execution directory: $!\n";
    die "unexpected temporary execution files: @left\n"
        if grep { $_ ne 'configs-runs' } @left;
    my (%logs, %new);
    if (@left) {
        my $directory = "$temporary/configs-runs";
        die "the run log directory must be a private owned directory\n"
            unless !-l $directory && -d $directory && ((stat($directory))[2] & 07777) == 0700
            && (stat($directory))[4] == $>;
        opendir(my $log_dir, $directory) or die "cannot inspect run logs: $!\n";
        my @entries = grep { $_ ne '.' && $_ ne '..' } readdir($log_dir);
        closedir($log_dir) or die "cannot close run log directory: $!\n";
        for my $entry (@entries) {
            my $path = "$directory/$entry";
            die "unexpected retained run log: $path\n"
                unless $entry =~ /\Atofu-(?:init|plan|show|apply)-[0-9]{8}T[0-9]{6}Z(?:-[0-9]+)?\.log\z/;
            die "the run log must be a private owned regular file: $path\n"
                unless !-l $path && -f $path && ((stat($path))[2] & 07777) == 0600
                && (stat($path))[4] == $>;
            open(my $file, '<:raw', $path) or die "cannot read run log $path: $!\n";
            local $/;
            my $content = <$file> // '';
            close($file) or die "cannot close run log $path: $!\n";
            for my $value (@$credentials) {
                die "run log exposed a fixture credential\n" if index($content, $value) >= 0;
            }
            $logs{$path} = sha256_hex($content);
            if (exists($previous->{$path})) {
                die "a retained run log changed: $path\n" unless $logs{$path} eq $previous->{$path};
            } else {
                die "the command did not announce its new run log: $path\n"
                    unless index($output, "Tofu output streams to $path\n") >= 0;
                $new{$path} = $content;
            }
        }
    }
    for my $path (keys %$previous) {
        die "the command removed a retained run log: $path\n" unless exists($logs{$path});
    }
    return (\%logs, \%new);
}

sub require_log_diagnostic {
    my ($logs, $kind, $message) = @_;
    my @matching = grep { m{/tofu-\Q$kind\E-} && index($logs->{$_}, $message) >= 0 } keys %$logs;
    die "the new $kind logs did not report $message\n" unless @matching;
}

sub capture_command {
    my ($directory, $credentials, $input, @args) = @_;
    my ($out) = tempfile(UNLINK => 1, DIR => $directory);
    my ($err) = tempfile(UNLINK => 1, DIR => $directory);
    my $pid = open3(my $writer, '>&' . fileno($out), '>&' . fileno($err), @args);
    print {$writer} $input or die "cannot write command input: $!\n" if length($input);
    close($writer) or die "cannot close command input: $!\n";
    waitpid($pid, 0) == $pid or die "cannot wait for $args[0]: $!\n";
    my $status = $?;
    my @output;
    for my $file ($out, $err) {
        seek($file, 0, 0) or die "cannot rewind command output: $!\n";
        local $/;
        push @output, scalar(<$file>) // '';
        for my $value (@$credentials) {
            die "command output exposed a fixture credential\n" if index($output[-1], $value) >= 0;
        }
    }
    my $label = join(' ', @args);
    die "$label stopped on signal " . ($status & 127) . "\n" if $status & 127;
    return ($status >> 8, \@output);
}

sub command {
    my ($context, $input, $expected, $diagnostic, @args) = @_;
    my ($code, $output) = capture_command($context->{directory}, $context->{credentials}, $input, @args);
    my @output = @$output;
    my $label = join(' ', @args);
    my ($logs, $new_logs) = check_run_logs("$context->{directory}/tmp", $context->{run_logs},
        join("\n", @output), $context->{credentials});
    $context->{run_logs} = $logs;
    die "$label exited with $code (expected $expected)\n$output[1]\n" if $code != $expected;
    if (defined($diagnostic)) {
        if (ref($diagnostic) eq 'HASH') {
            require_log_diagnostic($new_logs, $diagnostic->{log}, $diagnostic->{message});
        } else {
            die "$label did not report $diagnostic\n$output[1]\n"
                if index(join("\n", @output), $diagnostic) < 0;
        }
    }
    print "$label exited with $code\n";
    return @output;
}

sub tofu {
    my ($context, $code, $message, @args) = @_;
    return command($context, '', $code, $message, "$context->{directory}/bin/configsctl", 'tofu', 'sample', @args);
}

sub require_apply_lock {
    my ($stderr) = @_;
    my @selected = grep { /\bINFO tofu\.mutation\.explicit_lock_hosts(?:[ \t]|$)/ }
        split(/\n/, $stderr);
    die "the apply did not select exactly the hypervisor host\n"
        unless @selected == 1 && $selected[0] =~ /(?:^|[ \t])hosts=\[hypervisor\](?:[ \t]|\r?$)/;
    my @acquired = grep { /\bINFO hostlock\.acquired(?:[ \t]|$)/ } split(/\n/, $stderr);
    die "the apply did not acquire exactly one host lock\n"
        unless @acquired == 1 && $acquired[0] =~ /(?:^|[ \t])hosts=1(?:[ \t]|\r?$)/;
}

sub field {
    my ($pin, $name, $pattern) = @_;
    die "supply a valid $name in the installed-source pin\n"
        unless ref($pin) eq 'HASH' && defined($pin->{$name}) && !ref($pin->{$name});
    my ($validated) = $pin->{$name} =~ /\A($pattern)\z/;
    die "supply a valid $name in the installed-source pin\n" unless defined($validated);
    return $validated;
}

sub configuration {
    my ($context, $dir, $case, $pins) = @_;
    my $pin = $pins->{$case};
    die "supply the $case release pin\n" unless ref($pin) eq 'HASH';
    my $asset = field($pin, 'asset', qr/\A(hostconfig_[A-Za-z0-9_-]+\.tar\.gz)\z/);
    my $bundle = field($pin, 'bundle_asset', qr/\A([A-Za-z0-9_.-]+\.jsonl?)\z/);
    my $release = field($pin, 'release_tag', qr/\A(hostconfig-[A-Za-z0-9_-]+)\z/);
    my $revision = field($pin, 'source_revision', qr/\A([0-9a-f]{40})\z/);
    my $sha = field($pin, 'sha256', qr/\A([0-9a-f]{64})\z/);
    my $bundle_sha = field($pin, 'bundle_sha256', qr/\A([0-9a-f]{64})\z/);
    my $archive = "$dir/$case/$asset";
    my $bundle_path = "$dir/$case/$bundle";
    die "$case archive digest differs from its pin\n" unless digest($archive) eq $sha;
    die "$case attestation bundle digest differs from its pin\n"
        unless digest($bundle_path) eq $bundle_sha;
    my $tar = Archive::Tar->new;
    $tar->read($archive, 1) or die "cannot read $case archive\n";
    for my $entry ($tar->get_files) {
        assert_private($context, $entry->name . $entry->get_content, "$case archive member");
    }
    my $manifest = $tar->get_content('manifest.json') // die "$case lacks manifest.json\n";
    assert_private($context, HostArtifactsTest::read_file($bundle_path), "$case attestation bundle");
    return {
        archive => $archive, bundle => $bundle_path, asset => $asset, release_tag => $release,
        source_revision => $revision, sha256 => $sha, manifest_sha256 => sha256_hex($manifest),
    };
}

sub policy {
    my @files = map { { path => "$root/$_", mode => '0644', owner => 'root', group => 'root' } }
        qw(configsctl.yml native/main.tf workspaces/sample/main.tf workspaces/sample/host/main.tf);
    my @directories = map { { path => $_, mode => '0755', owner => 'root', group => 'root' } }
        ($root, map { "$root/$_" } qw(native workspaces workspaces/sample workspaces/sample/host));
    my $policy = HostArtifactsTest::base_policy($workspace, \@files, \@directories);
    die "run acceptance on the disposable hypervisor node\n" unless $policy->{node} eq 'hypervisor';
    return $policy;
}

sub install_release {
    my ($context, $rpcenv, $user, $pin) = @_;
    my %params = (
        'release-tag' => $pin->{release_tag}, asset => $pin->{asset},
        sha256 => $pin->{sha256}, 'source-revision' => $pin->{source_revision},
    );
    for my $kind (qw(archive bundle)) {
        $params{"$kind-stage"} = HostArtifactsTest::stage_file(
            $rpcenv, $user, $target, $kind, HostArtifactsTest::read_file($pin->{$kind}),
        );
    }
    my $response = HostArtifactsTest::api_request($rpcenv, $user, 'POST', $target, \%params);
    die "install returned status $response->{status}\n" if $response->{status} != 200;
    my ($status, $log) = HostArtifactsTest::wait_for_task($response->{data});
    assert_private($context, $log, 'install task log');
    die "install failed: $log\n" unless $status eq 'OK';
    die "install did not verify the configuration attestation\n"
        unless index($log, "gh attestation verify accepted $pin->{asset} with SHA-256 $pin->{sha256}") >= 0;
    print "Installed $pin->{release_tag} from $pin->{source_revision} with manifest $pin->{manifest_sha256}\n";
}

sub observation {
    my ($context) = @_;
    my ($stdout) = command($context, '', 0, undef, '/usr/bin/pvesh', 'get',
        "/nodes/localhost/host-artifacts/$target", '--output-format', 'json');
    return $context->{json}->decode($stdout);
}

sub verify_install {
    my ($context, $policy, $pin) = @_;
    my $state = observation($context);
    die "pvesh did not report a committed install\n" unless $state->{state} eq 'committed';
    for my $key (qw(workspace node environment)) {
        die "pvesh reported the wrong current or installed $key\n"
            unless $state->{$key} eq $policy->{$key} && $state->{installed}->{$key} eq $policy->{$key};
    }
    for my $key (qw(release_tag asset source_revision sha256 manifest_sha256)) {
        die "pvesh reported the wrong installed $key\n" unless $state->{installed}->{$key} eq $pin->{$key};
    }
    for my $kind (qw(files directories)) {
        my %expected = map { $_->{path} => $_ } @{$policy->{$kind}};
        for my $entry (@{$state->{$kind}}) {
            my $path = $entry->{path};
            my $wanted = delete($expected{$path}) // die "unexpected $kind entry: $path\n";
            die "pvesh reported drift for $path\n" unless $entry->{present} && $entry->{matches};
            for my $key (qw(mode owner group)) {
                die "unexpected $key for $path\n" unless $entry->{$key} eq $wanted->{$key};
            }
            if ($kind eq 'files') {
                my $bytes = HostArtifactsTest::read_file($wanted->{path});
                assert_private($context, $bytes, $wanted->{path});
                die "wrong observation for $path\n"
                    unless length($bytes) == $entry->{size} && sha256_hex($bytes) eq $entry->{sha256};
            }
        }
        die "pvesh omitted expected $kind\n" if keys %expected;
    }
}

sub check_plan {
    my ($context, $path) = @_;
    assert_private($context, HostArtifactsTest::read_file($path), 'saved plan');
    my $zip = IO::Uncompress::Unzip->new($path, Transparent => 0)
        or die "cannot open saved plan: $UnzipError\n";
    my $next;
    do {
        my $data = '';
        my $read;
        while (($read = $zip->read(my $block)) > 0) {
            $data .= $block;
        }
        die "cannot read saved plan: $UnzipError\n" if $read < 0;
        assert_private($context, $data, 'saved plan member');
        $next = $zip->nextStream();
    } while ($next > 0);
    die "cannot read saved plan member: $UnzipError\n" if $next < 0;
    $zip->close();
    my ($shown) = tofu($context, 0, undef, 'show', '-json', $path);
    return $context->{json}->decode($shown);
}

sub backend {
    my ($context, $version) = @_;
    my $bytes = HostArtifactsTest::read_file("$private/state.tfstate");
    assert_private($context, $bytes, 'backend state');
    my $state = $context->{json}->decode($bytes);
    my @marker = grep { ($_->{module} // '') eq 'module.host' && $_->{type} eq 'terraform_data'
        && $_->{name} eq 'marker' } @{$state->{resources}};
    die "expected one module.host.terraform_data.marker instance\n"
        unless @marker == 1 && @{$marker[0]->{instances}} == 1;
    my $input = $marker[0]->{instances}->[0]->{attributes}->{input};
    die "the backend marker does not contain $version\n" unless $input->{value} eq $version;
    die "the backend lacks its lineage or serial\n"
        unless $state->{lineage} && defined($state->{serial}) && $state->{serial} =~ /^\d+$/;
    return join(' ', sha256_hex($bytes), $state->{lineage}, $state->{serial});
}

sub random_token {
    open(my $random, '<:raw', '/dev/urandom') or die "cannot open the random device: $!\n";
    read($random, my $bytes, 32) == 32 or die "cannot read a fixture token: $!\n";
    close($random);
    return unpack('H*', $bytes);
}

sub set_token {
    my ($context, $token) = @_;
    command($context, "vault_installed_source_token: '$token'\n", 0, undef, "$context->{directory}/bin/configsctl", 'set-secrets');
    $ENV{TF_VAR_expected_token_sha256} = sha256_hex($token);
}

sub run {
    my ($rpcenv, $user, $dir) = @_;
    require HostArtifactsTest;
    my $context = {
        json => HostArtifactsTest::json(), credentials => [], run_logs => {}, directory => $private,
    };
    my $pins = read_json($context, "$dir/pins.json");
    my $policy = policy();
    my $seed_phrase = HostArtifactsTest::read_file('installed-source-seed.pass');
    chomp($seed_phrase);
    die "the empty Vault fixture requires its seed passphrase\n" unless length($seed_phrase);
    my ($first, $second) = (random_token(), random_token());
    $context->{credentials} = [$seed_phrase, $first, $second];
    my ($one, $two) = map { configuration($context, $dir, $_, $pins) } qw(installed-source-v1 installed-source-v2);
    die "publish both configurations from the same revision with different manifests\n"
        unless $one->{source_revision} eq $two->{source_revision} && $one->{manifest_sha256} ne $two->{manifest_sha256};
    # The empty ciphertext and its public test passphrase come from TestDecrypt
    # in the controller's ansible-vault-go v0.2.0 dependency.
    my $seed = HostArtifactsTest::read_file('installed-source-seed.vault');
    for my $path ($private, $root, $password_file) {
        die "acceptance requires a fresh disposable container: $path exists\n" if -e $path || -l $path;
    }
    umask(0077);
    make_path(map { "$private/$_" } qw(tmp bin data plans));
    local %ENV = (HOME => '/root', PATH => "$private/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        TMPDIR => "$private/tmp", TF_DATA_DIR => "$private/data", TF_IN_AUTOMATION => '1');
    for my $tool (qw(configsctl tofu)) {
        my $expected = field($pins->{$tool}, 'member_sha256', qr/\A([a-f0-9]{64})\z/);
        my $bytes = HostArtifactsTest::read_file("$dir/bin/$tool");
        die "$tool does not match its executable pin\n" unless sha256_hex($bytes) eq $expected;
        HostArtifactsTest::write_file("$private/bin/$tool", $bytes, 0700);
        print "$tool SHA-256 $expected\n";
    }
    command($context, '', 0, 'OpenTofu v1.13.2', "$private/bin/tofu", 'version');
    HostArtifactsTest::write_policy($policy);
    install_release($context, $rpcenv, $user, $one);
    verify_install($context, $policy, $one);

    make_path("$root/ansible/inventory/group_vars/all", '/root/.config/ansible', { mode => 0700 });
    HostArtifactsTest::write_file($vault, $seed, 0600);
    HostArtifactsTest::write_file($password_file, "$seed_phrase\n", 0600);
    chdir($root) or die "cannot enter the installed configuration: $!\n";
    set_token($context, $first);
    my ($version) = command($context, '', 0, undef, "$context->{directory}/bin/configsctl", 'version');
    print $version;
    tofu($context, 0, undef, 'init', '-input=false');
    {
        local $ENV{TF_VAR_expected_token_sha256} = sha256_hex($second);
        tofu($context, 1, { log => 'plan', message => 'The supplied token must match the expected SHA-256 digest.' },
            'plan', '-input=false', '-no-color');
    }
    my $plan = "$private/plans/first.tfplan";
    tofu($context, 0, undef, 'plan', '-input=false', "-out=$plan");
    check_plan($context, $plan);
    my (undef, $first_apply_stderr) = tofu($context, 0, undef, 'apply', '-input=false', $plan);
    require_apply_lock($first_apply_stderr);
    my $state = backend($context, 'one');
    tofu($context, 0, undef, 'plan', '-input=false', '-detailed-exitcode');
    my $encrypted = digest($vault);
    set_token($context, $second);
    die "rotation did not replace the encrypted Vault\n" if digest($vault) eq $encrypted;
    tofu($context, 0, undef, 'plan', '-input=false', '-detailed-exitcode');
    verify_install($context, $policy, $one);
    my $old = "$private/plans/old.tfplan";
    tofu($context, 0, undef, 'plan', '-input=false', '-replace=module.host.terraform_data.marker', "-out=$old");
    my $replacement = check_plan($context, $old);
    my @changes = grep { $_->{address} eq 'module.host.terraform_data.marker' }
        @{$replacement->{resource_changes}};
    die "the old plan must replace the installed marker\n"
        unless @changes == 1 && join(',', @{$changes[0]->{change}->{actions}}) eq 'delete,create';
    my $old_digest = digest($old);
    die "the repeat or replacement plan changed backend state\n" unless backend($context, 'one') eq $state;
    print "Backend SHA-256, lineage and serial: $state\nOld plan SHA-256: $old_digest\n";

    my $original = HostArtifactsTest::read_file($module);
    HostArtifactsTest::write_file($module, "$original\n", 0644);
    my @drift = grep { $_->{path} eq $module } @{observation($context)->{files}};
    die "pvesh did not report the altered module\n"
        unless @drift == 1 && exists($drift[0]->{matches}) && !$drift[0]->{matches};
    tofu($context, 1, "installed file $module must have a matching fresh observation", 'apply', '-input=false', $old);
    die "the altered-file refusal changed backend state\n" unless backend($context, 'one') eq $state;
    HostArtifactsTest::write_file($module, $original, 0644);
    verify_install($context, $policy, $one);

    HostArtifactsTest::write_policy({ %$policy, environment => 'other' });
    my $changed = observation($context);
    die "pvesh did not distinguish current and saved environments\n"
        unless $changed->{environment} eq 'other' && $changed->{installed}->{environment} eq 'testbed';
    tofu($context, 1, 'the current and saved installed workspace, node, and environment must match tofu.installed_source',
        'apply', '-input=false', $old);
    die "the identity refusal changed backend state\n" unless backend($context, 'one') eq $state;
    HostArtifactsTest::write_policy($policy);
    verify_install($context, $policy, $one);
    install_release($context, $rpcenv, $user, $two);
    verify_install($context, $policy, $two);
    die "the old plan changed before its apply\n" unless digest($old) eq $old_digest;
    tofu($context, 1, 'regenerate the saved plan from the current installed artifact; its recorded source does not match',
        'apply', '-input=false', $old);
    die "the stale-plan refusal changed backend state or plan bytes\n"
        unless backend($context, 'one') eq $state && digest($old) eq $old_digest;
    my $fresh = "$private/plans/fresh.tfplan";
    tofu($context, 0, undef, 'plan', '-input=false', "-out=$fresh");
    check_plan($context, $fresh);
    my (undef, $fresh_apply_stderr) = tofu($context, 0, undef, 'apply', '-input=false', $fresh);
    require_apply_lock($fresh_apply_stderr);
    my $final_state = backend($context, 'two');
    tofu($context, 0, undef, 'plan', '-input=false', '-detailed-exitcode');
    die "the final plan changed backend state\n" unless backend($context, 'two') eq $final_state;
    verify_install($context, $policy, $two);
    find({
        no_chdir => 1,
        wanted => sub {
            my $path = $File::Find::name;
            return unless -f $path;
            assert_private($context, HostArtifactsTest::read_file($path), $path);
        },
    }, $root, "$private/data");
    for my $path ($vault, $password_file) {
        die "the fixture credential file requires mode 0600\n" unless ((stat($path))[2] & 07777) == 0600;
    }
}

1;
