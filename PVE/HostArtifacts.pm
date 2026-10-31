package PVE::HostArtifacts;

use strict;
use warnings;

use Digest::SHA;
use Encode qw(encode_utf8);
use Errno qw(ENOENT ENOTEMPTY);
use Fcntl qw(:mode O_RDONLY O_WRONLY O_CREAT O_EXCL O_APPEND O_NOFOLLOW O_DIRECTORY);
use File::Basename qw(basename dirname);
use File::Path qw(make_path remove_tree);
use IO::Handle;
use IO::Uncompress::Gunzip qw($GunzipError);
use JSON;
use MIME::Base64 qw(decode_base64);
use POSIX qw(WNOHANG strftime);
use Time::HiRes qw();

use PVE::INotify;
use PVE::Tools;

my $POLICY_DIR = '/etc/pve-overlay/host-artifacts';
my $TARGET_POLICY_DIR = "$POLICY_DIR/targets";
my $TRUSTED_ROOT_FILE = "$POLICY_DIR/trusted_root.jsonl";
my $STATE_DIR = '/var/lib/pve-overlay/host-artifacts';
my $LOCK_FILE_PREFIX = '/run/lock/pve-overlay-host-artifact-';
my @PROTECTED_DIRS = ('/etc/pve-overlay', '/var/lib/pve-overlay');

my $GH_COMMAND = '/usr/bin/gh';
my $GH_HOST = 'github.com';
my $GH_TIMEOUT_SECONDS = 300;
my $GH_STDERR_LIMIT = 4096;
my $GH_POLL_SECONDS = 0.05;

my $SYSTEMCTL_COMMAND = '/usr/bin/systemctl';
my $UNIT_TIMEOUT_SECONDS = 300;
my $UNIT_STDERR_LIMIT = 1024;
my $SECRET_VALUE_MAX_LENGTH = 512;
my $SECRET_PATTERN_MAX_LENGTH = 1024;

# org.freedesktop.systemd1(5) lists these ActiveState values. A consumer unit counts as running
# in these states.
my $RUNNING_STATES = { map { $_ => 1 } qw(active activating reloading refreshing) };
# The task also restarts a failed unit because a failed restart of the field leaves the unit
# failed. The task does not restart an inactive, deactivating, or maintenance unit.
my $RESTART_STATES = { %$RUNNING_STATES, failed => 1 };

my $LOCK_TIMEOUT_SECONDS = 10;
my $STAGE_MAX_AGE_SECONDS = 3600;
my $POLICY_MAX_BYTES = 1024 * 1024;
my $RECORD_MAX_BYTES = 16 * 1024 * 1024;
my $MANIFEST_MAX_BYTES = 1024 * 1024;
my $MEMBER_MAX_COUNT = 512;
my $EXPANDED_MAX_BYTES = 512 * 1024 * 1024;
my $READ_BLOCK_BYTES = 64 * 1024;
my $TAR_BLOCK_BYTES = 512;
my $RANDOM_BYTES = 16;
my $STATE_FILE_MODE = 0600;
my $STATE_DIR_MODE = 0700;

my $SCHEMA_VERSION = 1;
my $MANIFEST_MEMBER = 'manifest.json';
my $FILES_PREFIX = 'files/';
my $STAGE_KINDS = { archive => 'max_archive_bytes', bundle => 'max_bundle_bytes' };

my $TARGET_RE = qr/[0-9a-f]{64}/;
my $STAGE_RE = qr/[0-9a-f]{32}/;
my $SHA256_RE = qr/[0-9a-f]{64}/;
my $REVISION_RE = qr/[0-9a-f]{40}/;
my $MODE_RE = qr/0[0-7]{3}/;
my $ACCOUNT_RE = qr/[a-z_][a-z0-9_-]{0,31}\$?/;
my $NODE_RE = qr/[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?/;
my $ENVIRONMENT_RE = qr/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/;
my $REPOSITORY_RE = qr/[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}/;
my $WORKFLOW_URI_RE = qr/https:\/\/[\x21-\x7e]{1,1024}/;
my $SOURCE_REF_RE = qr/refs\/[\x21-\x7e]{1,1024}/;
my $NAME_RE = qr/[A-Za-z0-9][A-Za-z0-9._-]{0,254}/;
my $BASE64_RE = qr{(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?};
my $SECRET_FIELD_RE = qr/[A-Z_][A-Z0-9_]{0,63}/;
my $UNIT_RE = qr/[A-Za-z0-9][A-Za-z0-9@._:-]{0,246}\.service/;
my $VERSION_RE = qr/[1-9][0-9]{0,15}/;

my $POLICY_KEYS = [
    qw(workspace node environment configuration directories parent_directories files
        secret_fields)
];
my $SECRET_FIELD_KEYS =
    [qw(name storage_path mode owner group pattern min_length max_length consumer_units)];
my $CONFIGURATION_KEYS =
    [qw(repository workflow_uri source_ref signer_digest max_archive_bytes max_bundle_bytes)];
my $ENTRY_KEYS = [qw(path mode owner group)];
my $MANIFEST_KEYS =
    [qw(schema_version repository source_revision workspace node environment directories files)];
my $MANIFEST_FILE_KEYS = [qw(member path size sha256 mode owner group)];
my $INSTALLED_KEYS =
    [qw(release_tag asset sha256 source_revision manifest_sha256 upid user installed_at)];

my $json = JSON->new->utf8->canonical;

# The function checks the value against the pattern and returns it without the taint flag.
my $untaint = sub {
    my ($value, $pattern, $label) = @_;

    die "$label is missing\n" if !defined($value) || ref($value);
    die "$label '$value' does not match the required pattern\n"
        if $value !~ m/\A($pattern)\z/;
    return $1;
};

my $check_keys = sub {
    my ($hash, $allowed, $label) = @_;

    die "$label is not a JSON object\n" if ref($hash) ne 'HASH';
    my %known = map { $_ => 1 } @$allowed;
    for my $key (sort keys %$hash) {
        die "$label has the unknown field '$key'\n" if !$known{$key};
    }
};

my $check_string = sub {
    my ($hash, $key, $pattern, $label) = @_;

    my $value = $hash->{$key};
    die "$label field '$key' is missing\n" if !defined($value);
    die "$label field '$key' is not a string\n" if ref($value);
    return $untaint->($value, $pattern, "$label field '$key'");
};

my $check_count = sub {
    my ($hash, $key, $label) = @_;

    my $value = $hash->{$key};
    die "$label field '$key' is missing\n" if !defined($value);
    die "$label field '$key' is not a nonnegative integer\n"
        if ref($value) || $value !~ m/\A(0|[1-9][0-9]{0,15})\z/;
    return $1 + 0;
};

my $random_hex = sub {
    open(my $handle, '<', '/dev/urandom') or die "cannot open /dev/urandom: $!\n";
    my $bytes = '';
    my $read = read($handle, $bytes, $RANDOM_BYTES);
    close($handle);
    die "cannot read /dev/urandom\n" if !defined($read) || $read != $RANDOM_BYTES;
    return $untaint->(unpack('H*', $bytes), qr/[0-9a-f]+/, 'random value');
};

# The function accepts every selector that validateWorkspaceSelector in configsctl accepts.
# A selector is a relative path. Each component must contain at least one character and must
# not start with a dot or equal terraform.d or modules. A selector cannot contain a backslash.
sub check_workspace_selector {
    my ($selector) = @_;

    die "workspace selector is missing\n" if !defined($selector) || ref($selector);
    die "workspace selector '$selector' must be a clean relative path\n"
        if $selector eq '' || $selector =~ m{\A/} || $selector =~ m{\\};
    for my $component (split(m{/}, $selector, -1)) {
        die "workspace selector '$selector' must be a clean relative path\n"
            if $component eq '' || $component =~ m/\A\./;
        die "workspace selector '$selector' contains an excluded directory\n"
            if $component eq 'terraform.d' || $component eq 'modules';
    }
    return $selector;
}

sub target_of_workspace {
    my ($selector) = @_;

    return Digest::SHA::sha256_hex(encode_utf8(check_workspace_selector($selector)));
}

sub check_target {
    my ($target) = @_;

    return $untaint->($target, $TARGET_RE, 'target');
}

# The function returns the path without the taint flag. The path is absolute and does not
# contain empty, '.', or '..' components. It is outside the directories with host artifact
# policy and records.
my $check_destination = sub {
    my ($path, $label) = @_;

    die "$label is missing\n" if !defined($path) || ref($path);
    my $message = "$label '$path' must be an absolute path without empty, '.', or '..'"
        . " components\n";
    die $message if $path !~ m{\A((?:/[^/\0]+)+)\z};
    my $untainted = $1;
    for my $component (split(m{/}, substr($untainted, 1))) {
        die $message if $component eq '.' || $component eq '..';
    }
    for my $protected (@PROTECTED_DIRS) {
        die "$label '$path' is inside $protected\n"
            if $untainted eq $protected || index($untainted, "$protected/") == 0;
    }
    return $untainted;
};

my $check_entry = sub {
    my ($entry, $label) = @_;

    $check_keys->($entry, $ENTRY_KEYS, $label);
    return {
        path => $check_destination->($entry->{path}, "$label path"),
        mode => $check_string->($entry, 'mode', $MODE_RE, $label),
        owner => $check_string->($entry, 'owner', $ACCOUNT_RE, $label),
        group => $check_string->($entry, 'group', $ACCOUNT_RE, $label),
    };
};

my $check_entries = sub {
    my ($list, $label) = @_;

    die "$label is not a JSON array\n" if ref($list) ne 'ARRAY';
    my $entries = {};
    for my $index (0 .. $#$list) {
        my $entry = $check_entry->($list->[$index], "$label\[$index\]");
        die "$label lists '$entry->{path}' more than once\n" if $entries->{ $entry->{path} };
        $entries->{ $entry->{path} } = $entry;
    }
    return $entries;
};

# The function validates the inspect-only parent directories of a policy. An entry has a path.
# The entry must list all three of mode, owner, and group or must not list any of them.
my $check_parent_entries = sub {
    my ($list, $label) = @_;

    die "$label is not a JSON array\n" if ref($list) ne 'ARRAY';
    my $entries = {};
    for my $index (0 .. $#$list) {
        my $raw = $list->[$index];
        my $entry_label = "$label\[$index\]";
        $check_keys->($raw, $ENTRY_KEYS, $entry_label);
        my $entry = { path => $check_destination->($raw->{path}, "$entry_label path") };
        my @present = grep { exists($raw->{$_}) } qw(mode owner group);
        if (@present) {
            die "$entry_label must list all three of mode, owner, and group or must not list"
                . " any of them\n"
                if scalar(@present) != 3;
            $entry->{mode} = $check_string->($raw, 'mode', $MODE_RE, $entry_label);
            $entry->{owner} = $check_string->($raw, 'owner', $ACCOUNT_RE, $entry_label);
            $entry->{group} = $check_string->($raw, 'group', $ACCOUNT_RE, $entry_label);
        }
        die "$label lists '$entry->{path}' more than once\n" if $entries->{ $entry->{path} };
        $entries->{ $entry->{path} } = $entry;
    }
    return $entries;
};

my $same_entry = sub {
    my ($left, $right) = @_;

    for my $key (@$ENTRY_KEYS) {
        return 0 if $left->{$key} ne $right->{$key};
    }
    return 1;
};

my $read_limited = sub {
    my ($path, $limit) = @_;

    sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW) or die "cannot read $path: $!\n";
    my @stat = stat($handle);
    die "$path is not a regular file\n" if !S_ISREG($stat[2]);
    die "$path is larger than $limit bytes\n" if $stat[7] > $limit;
    my $content = '';
    while (1) {
        my $read = sysread($handle, $content, $READ_BLOCK_BYTES, length($content));
        die "cannot read $path: $!\n" if !defined($read);
        last if $read == 0;
        die "$path is larger than $limit bytes\n" if length($content) > $limit;
    }
    close($handle);
    return $content;
};

my $decode_json_file = sub {
    my ($path, $limit) = @_;

    my $content = $read_limited->($path, $limit);
    my $value = eval { $json->decode($content) };
    die "$path is not valid JSON: $@" if $@;
    return $value;
};

# A trust file and each directory above it must belong to root, must not be writable by the
# group or other users, and must not be a symbolic link.
my $check_root_owned = sub {
    my ($path) = @_;

    my $current = '';
    for my $component (split(m{/}, substr($path, 1))) {
        $current .= "/$component";
        my @stat = lstat($current);
        die "$current does not exist\n" if !@stat;
        die "$current is a symbolic link\n" if S_ISLNK($stat[2]);
        die "$current must belong to root\n" if $stat[4] != 0;
        die "$current must not be writable by the group or other users\n" if $stat[2] & 022;
    }
};

# The function validates the secret fields of a policy. Each field has its own storage file
# outside the policy files and directories. The function anchors the pattern at both ends.
my $check_secret_fields = sub {
    my ($list, $label, $files, $directories) = @_;

    die "$label is not a JSON array\n" if ref($list) ne 'ARRAY';
    my $fields = {};
    my $paths = {};
    for my $index (0 .. $#$list) {
        my $raw = $list->[$index];
        my $entry_label = "$label\[$index\]";
        $check_keys->($raw, $SECRET_FIELD_KEYS, $entry_label);
        my $name = $check_string->($raw, 'name', $SECRET_FIELD_RE, $entry_label);
        die "$label lists the field $name more than once\n" if $fields->{$name};
        my $path = $check_destination->($raw->{storage_path}, "$entry_label storage_path");
        die "$label lists the storage path $path more than once\n" if $paths->{$path}++;
        die "$entry_label storage_path $path is also a policy file or directory\n"
            if $files->{$path} || $directories->{$path};

        my $pattern_text = $check_string->(
            $raw, 'pattern', qr/[^\0]{1,$SECRET_PATTERN_MAX_LENGTH}/s, $entry_label,
        );
        my $pattern = eval { qr/\A(?:$pattern_text)\z/ };
        die "$entry_label pattern is not a valid regular expression\n" if !$pattern;
        my $min_length = $check_count->($raw, 'min_length', $entry_label);
        my $max_length = $check_count->($raw, 'max_length', $entry_label);
        die "$entry_label needs 1 <= min_length <= max_length <= $SECRET_VALUE_MAX_LENGTH\n"
            if $min_length < 1
            || $min_length > $max_length
            || $max_length > $SECRET_VALUE_MAX_LENGTH;

        die "$entry_label consumer_units is not a JSON array\n"
            if ref($raw->{consumer_units}) ne 'ARRAY';
        my $units = [];
        my $seen_units = {};
        for my $unit (@{ $raw->{consumer_units} }) {
            my $checked = $untaint->($unit, $UNIT_RE, "$entry_label consumer unit");
            die "$entry_label lists the consumer unit $checked more than once\n"
                if $seen_units->{$checked}++;
            push @$units, $checked;
        }

        $fields->{$name} = {
            name => $name,
            path => $path,
            mode => $check_string->($raw, 'mode', $MODE_RE, $entry_label),
            owner => $check_string->($raw, 'owner', $ACCOUNT_RE, $entry_label),
            group => $check_string->($raw, 'group', $ACCOUNT_RE, $entry_label),
            pattern => $pattern,
            min_length => $min_length,
            max_length => $max_length,
            consumer_units => $units,
        };
    }
    return $fields;
};

sub policy_path {
    my ($target) = @_;

    return "$TARGET_POLICY_DIR/" . check_target($target) . '.json';
}

sub trusted_root_path {
    return $TRUSTED_ROOT_FILE;
}

# The function reads and validates only the policy file of the selected target.
sub load_policy {
    my ($target) = @_;

    $target = check_target($target);
    my $path = policy_path($target);
    die "the host artifact policy $path does not exist\n" if !-e $path;
    $check_root_owned->($path);
    my $document = $decode_json_file->($path, $POLICY_MAX_BYTES);
    my $label = "policy $path";

    $check_keys->($document, $POLICY_KEYS, $label);
    my $workspace = check_workspace_selector($document->{workspace});
    my $workspace_target = target_of_workspace($workspace);
    die "$label workspace '$workspace' has the target $workspace_target, not $target\n"
        if $workspace_target ne $target;

    my $configuration = $document->{configuration};
    my $configuration_label = "$label configuration";
    $check_keys->($configuration, $CONFIGURATION_KEYS, $configuration_label);
    my $checked_configuration = {
        repository => $check_string->(
            $configuration, 'repository', $REPOSITORY_RE, $configuration_label,
        ),
        workflow_uri => $check_string->(
            $configuration, 'workflow_uri', $WORKFLOW_URI_RE, $configuration_label,
        ),
        source_ref => $check_string->(
            $configuration, 'source_ref', $SOURCE_REF_RE, $configuration_label,
        ),
        max_archive_bytes => $check_count->(
            $configuration, 'max_archive_bytes', $configuration_label,
        ),
        max_bundle_bytes => $check_count->(
            $configuration, 'max_bundle_bytes', $configuration_label,
        ),
    };
    if (exists($configuration->{signer_digest})) {
        $checked_configuration->{signer_digest} = $check_string->(
            $configuration, 'signer_digest', $REVISION_RE, $configuration_label,
        );
    }

    my $directories = $check_entries->($document->{directories}, "$label directories");
    my $parents = $check_parent_entries->(
        $document->{parent_directories} // [], "$label parent_directories",
    );
    my $files = $check_entries->($document->{files}, "$label files");
    for my $path (sort keys %$files) {
        die "$label lists '$path' as a file and as a directory\n"
            if $directories->{$path} || $parents->{$path};
    }
    for my $path (sort keys %$parents) {
        die "$label lists '$path' in directories and in parent_directories\n"
            if $directories->{$path};
    }
    my $secret_fields = $check_secret_fields->(
        $document->{secret_fields} // [],
        "$label secret_fields",
        $files,
        { %$directories, %$parents },
    );

    return {
        target => $target,
        path => $path,
        workspace => $workspace,
        node => $check_string->($document, 'node', $NODE_RE, $label),
        environment => $check_string->($document, 'environment', $ENVIRONMENT_RE, $label),
        configuration => $checked_configuration,
        directories => $directories,
        parents => $parents,
        files => $files,
        secret_fields => $secret_fields,
    };
}

sub check_node {
    my ($policy) = @_;

    my $nodename = PVE::INotify::nodename();
    die "policy $policy->{path} is for node '$policy->{node}', and this node is '$nodename'\n"
        if $policy->{node} ne $nodename;
}

my $target_dir = sub {
    my ($target) = @_;

    return "$STATE_DIR/" . check_target($target);
};

my $stage_dir = sub {
    my ($target) = @_;

    return $target_dir->($target) . '/stages';
};

my $journal_path = sub {
    my ($target) = @_;

    return $target_dir->($target) . '/journal.json';
};

my $installed_path = sub {
    my ($target) = @_;

    return $target_dir->($target) . '/installed.json';
};

my $ensure_target_dir = sub {
    my ($target) = @_;

    my @dirs = ($STATE_DIR, $target_dir->($target), $stage_dir->($target));
    make_path(@dirs, { mode => $STATE_DIR_MODE });
    for my $path (@dirs) {
        chmod($STATE_DIR_MODE, $path) or die "cannot change the mode of $path: $!\n";
    }
};

sub with_target_lock {
    my ($target, $code) = @_;

    my $lock_path = $LOCK_FILE_PREFIX . check_target($target) . '.lck';
    my $result = PVE::Tools::lock_file($lock_path, $LOCK_TIMEOUT_SECONDS, $code);
    die $@ if $@;
    return $result;
}

my $sync_dir = sub {
    my ($dir) = @_;

    sysopen(my $handle, $dir, O_RDONLY | O_DIRECTORY)
        or die "cannot open the directory $dir: $!\n";
    $handle->sync() or die "cannot sync the directory $dir: $!\n";
    close($handle);
};

my $write_all = sub {
    my ($handle, $bytes, $path) = @_;

    my $offset = 0;
    while ($offset < length($bytes)) {
        my $written = syswrite($handle, $bytes, length($bytes) - $offset, $offset);
        die "cannot write $path: $!\n" if !defined($written);
        $offset += $written;
    }
};

# The function writes a temporary file in the same directory, syncs it, and renames it to
# the destination. The function then syncs the directory.
my $write_file_atomic = sub {
    my ($path, $content, $mode) = @_;

    my $temporary = "$path.tmp";
    unlink($temporary) or $! == ENOENT or die "cannot delete $temporary: $!\n";
    sysopen(my $handle, $temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, $mode)
        or die "cannot create $temporary: $!\n";
    $write_all->($handle, $content, $temporary);
    $handle->sync() or die "cannot sync $temporary: $!\n";
    close($handle) or die "cannot close $temporary: $!\n";
    rename($temporary, $path) or die "cannot rename $temporary to $path: $!\n";
    $sync_dir->(dirname($path));
};

my $read_stage_record = sub {
    my ($target, $stage) = @_;

    $stage = $untaint->($stage, $STAGE_RE, 'stage');
    my $record_path = $stage_dir->($target) . "/$stage.json";
    return undef if !-e $record_path;
    my $record = $decode_json_file->($record_path, $POLICY_MAX_BYTES);
    die "the stage record $record_path is not valid\n"
        if ref($record) ne 'HASH'
        || !defined($record->{user})
        || !defined($record->{kind})
        || !defined($record->{created});
    return {
        stage => $stage,
        user => $record->{user},
        kind => $record->{kind},
        created => $record->{created},
        data_path => $stage_dir->($target) . "/$stage",
        record_path => $record_path,
    };
};

my $stage_length = sub {
    my ($record) = @_;

    my @stat = lstat($record->{data_path});
    die "stage $record->{stage} does not have a data file\n" if !@stat;
    die "the data of stage $record->{stage} is not a regular file\n" if !S_ISREG($stat[2]);
    return $stat[7];
};

# The function checks that the stage exists for the target and matches the user and kind.
# The function returns the stage record.
sub check_stage {
    my ($target, $stage, $user, $kind) = @_;

    my $record = $read_stage_record->($target, $stage);
    die "stage $stage does not exist for this target\n" if !$record;
    die "stage $stage belongs to another user\n" if $record->{user} ne $user;
    die "stage $stage has the kind $record->{kind}, not $kind\n" if $record->{kind} ne $kind;
    $stage_length->($record);
    return $record;
}

my $remove_path = sub {
    my ($path) = @_;

    unlink($path) or $! == ENOENT or die "cannot delete $path: $!\n";
};

my $remove_stage = sub {
    my ($record) = @_;

    $remove_path->($record->{data_path});
    $remove_path->($record->{record_path});
};

my $read_journal = sub {
    my ($target) = @_;

    my $path = $journal_path->($target);
    return undef if !-e $path;
    my $journal = $decode_json_file->($path, $RECORD_MAX_BYTES);
    die "$path is not valid\n"
        if ref($journal) ne 'HASH'
        || ref($journal->{files}) ne 'ARRAY'
        || ref($journal->{directories}) ne 'ARRAY'
        || !defined($journal->{phase});
    return $journal;
};

# The function deletes stages of the target that are older than one hour and that the journal
# does not list. The caller acquires the target lock before calling this function.
my $expire_stages = sub {
    my ($target) = @_;

    my $journal = $read_journal->($target);
    my $referenced = {};
    if ($journal) {
        for my $key (qw(archive_stage bundle_stage)) {
            $referenced->{ $journal->{$key} } = 1 if defined($journal->{$key});
        }
    }

    my $dir = $stage_dir->($target);
    opendir(my $handle, $dir) or die "cannot read $dir: $!\n";
    my @names = readdir($handle);
    closedir($handle);
    my $now = time();
    for my $name (sort @names) {
        next if $name !~ m/\A($STAGE_RE)\.json\z/;
        my $stage = $1;
        next if $referenced->{$stage};
        my $record = $read_stage_record->($target, $stage);
        next if !$record || $now - $record->{created} < $STAGE_MAX_AGE_SECONDS;
        $remove_stage->($record);
    }
};

my $append_chunk = sub {
    my ($path, $bytes, $flags) = @_;

    sysopen(my $handle, $path, $flags, $STATE_FILE_MODE) or die "cannot open $path: $!\n";
    $write_all->($handle, $bytes, $path);
    $handle->sync() or die "cannot sync $path: $!\n";
    close($handle) or die "cannot close $path: $!\n";
};

# The function adds one chunk to a stage. Offset 0 creates a new stage. Every other offset
# must equal the current length of the stage.
sub stage_chunk {
    my ($target, $user, $kind, $offset, $data, $stage) = @_;

    die "the stage kind is not archive or bundle\n"
        if !defined($kind) || !$STAGE_KINDS->{$kind};
    $kind = $untaint->($kind, qr/archive|bundle/, 'kind');
    $offset = $untaint->($offset, qr/[0-9]{1,16}/, 'offset') + 0;
    my $policy = load_policy($target);
    check_node($policy);
    my $limit = $policy->{configuration}->{ $STAGE_KINDS->{$kind} };
    die "parameter 'data' is not valid base64\n" if $data !~ m/\A$BASE64_RE\z/;
    my $bytes = decode_base64($data);

    return with_target_lock(
        $policy->{target},
        sub {
            $ensure_target_dir->($policy->{target});
            $expire_stages->($policy->{target});

            my $record;
            if ($offset == 0) {
                die "parameter 'stage' must be omitted at offset 0\n" if defined($stage);
                die "the $kind is larger than $limit bytes\n" if length($bytes) > $limit;
                my $new_stage = substr($random_hex->(), 0, 32);
                my $record_path = $stage_dir->($policy->{target}) . "/$new_stage.json";
                $write_file_atomic->(
                    $record_path,
                    $json->encode({ user => $user, kind => $kind, created => time() }),
                    $STATE_FILE_MODE,
                );
                $record = $read_stage_record->($policy->{target}, $new_stage);
                $append_chunk->($record->{data_path}, $bytes, O_WRONLY | O_CREAT | O_EXCL);
            } else {
                die "parameter 'stage' is required at offset $offset\n" if !defined($stage);
                $record = check_stage($policy->{target}, $stage, $user, $kind);
                my $length = $stage_length->($record);
                die "offset $offset does not equal the stage length $length\n"
                    if $offset != $length;
                die "the $kind is larger than $limit bytes\n"
                    if $length + length($bytes) > $limit;
                $append_chunk->($record->{data_path}, $bytes, O_WRONLY | O_APPEND);
            }
            return { stage => $record->{stage}, length => $stage_length->($record) };
        },
    );
}

my $sha256_file = sub {
    my ($path) = @_;

    sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW) or die "cannot read $path: $!\n";
    my $digest = Digest::SHA->new(256);
    $digest->addfile($handle);
    close($handle);
    return $digest->hexdigest();
};

# The function runs gh with only HOME, GH_CONFIG_DIR, and GH_HOST in the environment. It
# returns the wait status, the standard output, and at most 4 KiB of the standard error.
my $run_gh = sub {
    my ($work_dir, $arguments) = @_;

    my $stdout_path = "$work_dir/stdout";
    my $stderr_path = "$work_dir/stderr";
    my $pid = fork() // die "cannot fork: $!\n";
    if (!$pid) {
        eval {
            open(STDIN, '<', '/dev/null') or die "cannot open /dev/null: $!\n";
            open(STDOUT, '>', $stdout_path) or die "cannot open $stdout_path: $!\n";
            open(STDERR, '>', $stderr_path) or die "cannot open $stderr_path: $!\n";
            %ENV = (HOME => $work_dir, GH_CONFIG_DIR => $work_dir, GH_HOST => $GH_HOST);
            exec { $GH_COMMAND } $GH_COMMAND, @$arguments;
            die "cannot run $GH_COMMAND: $!\n";
        };
        print STDERR $@;
        POSIX::_exit(127);
    }

    my $deadline = Time::HiRes::time() + $GH_TIMEOUT_SECONDS;
    my $status;
    while (1) {
        my $waited = waitpid($pid, WNOHANG);
        if ($waited == $pid) {
            $status = $?;
            last;
        }
        die "cannot wait for $GH_COMMAND: $!\n" if $waited < 0;
        if (Time::HiRes::time() > $deadline) {
            kill('KILL', $pid);
            waitpid($pid, 0);
            die "$GH_COMMAND did not exit within $GH_TIMEOUT_SECONDS seconds\n";
        }
        Time::HiRes::sleep($GH_POLL_SECONDS);
    }

    my $stdout = $read_limited->($stdout_path, $RECORD_MAX_BYTES);
    my $stderr = substr($read_limited->($stderr_path, $RECORD_MAX_BYTES), 0, $GH_STDERR_LIMIT);
    return ($status, $stdout, $stderr);
};

# The function runs gh attestation verify offline with the policy identity, the trusted root,
# and the bundle. Every verified statement must have a subject with the requested asset name
# and SHA-256, and the SHA-256 of the archive must equal the request.
sub verify_attestation {
    my ($policy, $request, $archive_path, $bundle_path) = @_;

    my $configuration = $policy->{configuration};
    die "the trusted root $TRUSTED_ROOT_FILE does not exist\n" if !-e $TRUSTED_ROOT_FILE;
    $check_root_owned->($TRUSTED_ROOT_FILE);

    $ensure_target_dir->($policy->{target});
    my $work_dir = $target_dir->($policy->{target}) . '/work-' . $random_hex->();
    mkdir($work_dir, $STATE_DIR_MODE) or die "cannot create $work_dir: $!\n";

    # gh accepts a bundle only in a file that ends in .json or .jsonl.
    my $bundle_copy = "$work_dir/bundle.jsonl";
    my @arguments = (
        'attestation', 'verify', $archive_path,
        '--hostname', $GH_HOST,
        '--repo', $configuration->{repository},
        '--cert-identity', $configuration->{workflow_uri},
        '--source-digest', $request->{source_revision},
        '--source-ref', $configuration->{source_ref},
    );
    push @arguments, '--signer-digest', $configuration->{signer_digest}
        if defined($configuration->{signer_digest});
    push @arguments,
        '--deny-self-hosted-runners',
        '--bundle', $bundle_copy,
        '--custom-trusted-root', $TRUSTED_ROOT_FILE,
        '--format', 'json';

    my ($status, $stdout, $stderr) = eval {
        my $bundle = $read_limited->($bundle_path, $configuration->{max_bundle_bytes});
        sysopen(my $handle, $bundle_copy, O_WRONLY | O_CREAT | O_EXCL, $STATE_FILE_MODE)
            or die "cannot create $bundle_copy: $!\n";
        $write_all->($handle, $bundle, $bundle_copy);
        close($handle) or die "cannot close $bundle_copy: $!\n";
        $run_gh->($work_dir, \@arguments);
    };
    my $error = $@;
    remove_tree($work_dir);
    die $error if $error;

    if ($status != 0) {
        my $exit_code = $status >> 8;
        die "gh attestation verify exited with code $exit_code: $stderr\n";
    }

    my $results = eval { $json->decode($stdout) };
    die "gh attestation verify did not print JSON: $@" if $@;
    die "gh attestation verify did not return a verified statement\n"
        if ref($results) ne 'ARRAY' || !@$results;
    for my $result (@$results) {
        my $subjects = ref($result) eq 'HASH'
            && ref($result->{verificationResult}) eq 'HASH'
            && ref($result->{verificationResult}->{statement}) eq 'HASH'
            ? $result->{verificationResult}->{statement}->{subject}
            : undef;
        die "gh attestation verify returned a statement without subjects\n"
            if ref($subjects) ne 'ARRAY';
        my $found = grep {
            ref($_) eq 'HASH'
                && ($_->{name} // '') eq $request->{asset}
                && ref($_->{digest}) eq 'HASH'
                && ($_->{digest}->{sha256} // '') eq $request->{sha256}
        } @$subjects;
        die "a verified statement does not have the subject $request->{asset} with SHA-256"
            . " $request->{sha256}\n"
            if !$found;
    }

    my $archive_sha256 = $sha256_file->($archive_path);
    die "the staged archive has SHA-256 $archive_sha256, and the request has"
        . " $request->{sha256}\n"
        if $archive_sha256 ne $request->{sha256};
}

my $read_exact = sub {
    my ($stream, $length, $label) = @_;

    my $buffer = '';
    while (length($buffer) < $length) {
        my $read = $stream->read($buffer, $length - length($buffer), length($buffer));
        die "cannot read the archive: $GunzipError\n" if !defined($read) || $read < 0;
        die "the archive ends inside $label\n" if $read == 0;
    }
    return $buffer;
};

my $parse_octal = sub {
    my ($field, $label) = @_;

    die "the archive header field $label is not an octal number\n"
        if $field !~ m/\A *([0-7]+)[ \0]*\z/;
    return oct($1);
};

my $tar_field = sub {
    my ($field, $label) = @_;

    my $end = index($field, "\0");
    return $field if $end < 0;
    die "the archive header field $label has bytes after its terminator\n"
        if substr($field, $end) !~ m/\A\0*\z/;
    return substr($field, 0, $end);
};

my $check_member_name = sub {
    my ($name) = @_;

    die "an archive member has an empty name\n" if $name eq '';
    die "the archive member '$name' has an absolute name\n" if $name =~ m{\A/};
    die "the archive member '$name' contains a backslash\n" if $name =~ m{\\};
    for my $component (split(m{/}, $name, -1)) {
        die "the archive member '$name' has an empty, '.', or '..' component\n"
            if $component eq '' || $component eq '.' || $component eq '..';
    }
    return $name;
};

my $read_end_of_archive = sub {
    my ($stream) = @_;

    my $second = $read_exact->($stream, $TAR_BLOCK_BYTES, 'the end marker');
    die "the archive end marker is not two zero blocks\n" if $second ne "\0" x $TAR_BLOCK_BYTES;
    while (1) {
        my $buffer = '';
        my $read = $stream->read($buffer, $READ_BLOCK_BYTES);
        die "cannot read the archive: $GunzipError\n" if !defined($read) || $read < 0;
        last if $read == 0;
        die "the archive has data after its end marker\n" if $buffer =~ m/[^\0]/;
    }
    die "the gzip stream has data after its end\n" if length($stream->trailingData() // '');
};

# The function reads a gzip ustar archive and calls $on_member for each member. Every member
# must be a regular file. $on_member returns undef or a code reference that receives the bytes
# of the member. The function returns the members with name, size, mode, and SHA-256.
sub scan_archive {
    my ($path, $on_member) = @_;

    my $stream = IO::Uncompress::Gunzip->new(
        $path,
        MultiStream => 0,
        Transparent => 0,
        Strict => 1,
        AutoClose => 1,
    ) or die "cannot open the archive $path: $GunzipError\n";

    my $members = [];
    my $seen = {};
    my $expanded = 0;
    while (1) {
        my $header = $read_exact->($stream, $TAR_BLOCK_BYTES, 'a header');
        if ($header eq "\0" x $TAR_BLOCK_BYTES) {
            $read_end_of_archive->($stream);
            last;
        }

        my ($name, $mode, $size, $checksum, $type, $link_name, $magic, $version, $prefix) =
            unpack('a100 a8 x8 x8 a12 x12 a8 a1 a100 a6 a2 x32 x32 x8 x8 a155', $header);

        my $computed_checksum =
            unpack('%32C*', substr($header, 0, 148) . (' ' x 8) . substr($header, 156));
        die "the archive header checksum does not match\n"
            if $computed_checksum != $parse_octal->($checksum, 'chksum');
        die "the archive is not a POSIX ustar archive\n"
            if $magic ne "ustar\0" || $version ne '00';

        $name = $tar_field->($name, 'name');
        $prefix = $tar_field->($prefix, 'prefix');
        $name = "$prefix/$name" if $prefix ne '';
        $name = $check_member_name->($name);
        die "the archive member '$name' is not a regular file\n" if $type ne '0';
        die "the archive member '$name' has a link target\n"
            if $tar_field->($link_name, 'linkname') ne '';
        die "the archive lists the member '$name' more than once\n" if $seen->{$name}++;
        die "the archive has more than " . ($MEMBER_MAX_COUNT + 1) . " members\n"
            if scalar(@$members) > $MEMBER_MAX_COUNT;

        my $member_mode = $parse_octal->($mode, 'mode');
        die "the archive member '$name' has mode bits outside 0777\n" if $member_mode & ~0777;
        my $member_size = $parse_octal->($size, 'size');
        $expanded += $member_size;
        die "the archive expands to more than $EXPANDED_MAX_BYTES bytes\n"
            if $expanded > $EXPANDED_MAX_BYTES;

        my $sink = $on_member->({ name => $name, size => $member_size, mode => $member_mode });
        my $digest = Digest::SHA->new(256);
        my $remaining = $member_size;
        while ($remaining > 0) {
            my $length = $remaining < $READ_BLOCK_BYTES ? $remaining : $READ_BLOCK_BYTES;
            my $bytes = $read_exact->($stream, $length, "the member '$name'");
            $digest->add($bytes);
            $sink->($bytes) if $sink;
            $remaining -= $length;
        }
        my $padding = (-$member_size) % $TAR_BLOCK_BYTES;
        if ($padding) {
            my $bytes = $read_exact->($stream, $padding, "the padding of '$name'");
            die "the padding of the archive member '$name' is not zero\n" if $bytes =~ m/[^\0]/;
        }
        push @$members, {
            name => $name,
            size => $member_size,
            mode => $member_mode,
            sha256 => $digest->hexdigest(),
        };
    }
    $stream->close();
    return $members;
}

my $account_ids = sub {
    my ($owner, $group) = @_;

    my $uid = getpwnam($owner);
    die "the user '$owner' does not exist on this node\n" if !defined($uid);
    my $gid = getgrnam($group);
    die "the group '$group' does not exist on this node\n" if !defined($gid);
    return ($uid, $gid);
};

my $compare_field = sub {
    my ($field, $actual, $expected) = @_;

    $actual = '' if !defined($actual) || ref($actual);
    die "the manifest $field is '$actual', and the expected value is '$expected'\n"
        if $actual ne $expected;
};

# The function validates the manifest against the request, the policy, and the local node.
# It validates the archive members against the manifest. The function does not write a file.
sub validate_archive {
    my ($policy, $request, $archive_path) = @_;

    my $manifest_content;
    my $members = scan_archive(
        $archive_path,
        sub {
            my ($member) = @_;
            return undef if $member->{name} ne $MANIFEST_MEMBER;
            die "$MANIFEST_MEMBER is larger than $MANIFEST_MAX_BYTES bytes\n"
                if $member->{size} > $MANIFEST_MAX_BYTES;
            $manifest_content = '';
            return sub { $manifest_content .= $_[0] };
        },
    );
    die "the archive does not contain $MANIFEST_MEMBER\n" if !defined($manifest_content);

    my $manifest = eval { $json->decode($manifest_content) };
    die "$MANIFEST_MEMBER is not valid JSON: $@" if $@;
    my $label = 'the manifest';
    $check_keys->($manifest, $MANIFEST_KEYS, $label);
    die "the manifest schema_version is not $SCHEMA_VERSION\n"
        if !defined($manifest->{schema_version})
        || ref($manifest->{schema_version})
        || "$manifest->{schema_version}" ne "$SCHEMA_VERSION";

    $compare_field->(
        'repository', $manifest->{repository}, $policy->{configuration}->{repository},
    );
    $compare_field->(
        'source_revision', $manifest->{source_revision}, $request->{source_revision},
    );
    $compare_field->('workspace', $manifest->{workspace}, $policy->{workspace});
    $compare_field->('node', $manifest->{node}, $policy->{node});
    $compare_field->('node', $manifest->{node}, PVE::INotify::nodename());
    $compare_field->('environment', $manifest->{environment}, $policy->{environment});

    my $listed = $check_entries->($manifest->{directories}, "$label directories");
    my $directories = {};
    my $inspected = {};
    for my $path (sort keys %$listed) {
        # A manifest directory that the policy lists as an inspect-only parent stays as it is.
        if ($policy->{parents}->{$path}) {
            $inspected->{$path} = 1;
            next;
        }
        $directories->{$path} = $listed->{$path};
        my $allowed = $policy->{directories}->{$path};
        die "the policy does not list the directory $path\n" if !$allowed;
        die "the directory $path does not match the mode, owner, and group in the policy\n"
            if !$same_entry->($directories->{$path}, $allowed);
        @{ $directories->{$path} }{qw(uid gid)} =
            $account_ids->($directories->{$path}->{owner}, $directories->{$path}->{group});
    }

    die "the manifest files field is not a JSON array\n" if ref($manifest->{files}) ne 'ARRAY';
    my $files = {};
    my $expected_members = { $MANIFEST_MEMBER => undef };
    for my $index (0 .. $#{ $manifest->{files} }) {
        my $raw = $manifest->{files}->[$index];
        my $file_label = "$label files\[$index\]";
        $check_keys->($raw, $MANIFEST_FILE_KEYS, $file_label);
        my $entry = $check_entry->({ map { $_ => $raw->{$_} } @$ENTRY_KEYS }, $file_label);
        my $path = $entry->{path};
        die "the manifest lists the file $path more than once\n" if $files->{$path};
        my $allowed = $policy->{files}->{$path};
        die "the policy does not list the file $path\n" if !$allowed;
        die "the file $path does not match the mode, owner, and group in the policy\n"
            if !$same_entry->($entry, $allowed);
        my $expected_member = $FILES_PREFIX . substr($path, 1);
        my $member = $check_string->($raw, 'member', qr/[^\0]+/, $file_label);
        die "the manifest member of $path is '$member', not '$expected_member'\n"
            if $member ne $expected_member;
        $entry->{member} = $member;
        $entry->{size} = $check_count->($raw, 'size', $file_label);
        $entry->{sha256} = $check_string->($raw, 'sha256', $SHA256_RE, $file_label);
        @$entry{qw(uid gid)} = $account_ids->($entry->{owner}, $entry->{group});
        $files->{$path} = $entry;
        $expected_members->{$member} = $entry;
    }

    my $actual_members = { map { $_->{name} => $_ } @$members };
    for my $name (sort keys %$actual_members) {
        die "the archive member '$name' is not in the manifest\n"
            if !exists($expected_members->{$name});
    }
    for my $name (sort keys %$expected_members) {
        my $actual = $actual_members->{$name};
        die "the archive does not contain the member '$name'\n" if !$actual;
        my $expected = $expected_members->{$name} // next;
        die "the archive member '$name' has $actual->{size} bytes, and the manifest lists"
            . " $expected->{size}\n"
            if $actual->{size} != $expected->{size};
        die "the archive member '$name' has SHA-256 $actual->{sha256}, and the manifest lists"
            . " $expected->{sha256}\n"
            if $actual->{sha256} ne $expected->{sha256};
    }

    return {
        manifest_sha256 => Digest::SHA::sha256_hex($manifest_content),
        directories => $directories,
        inspected => $inspected,
        files => $files,
    };
}

# The function returns the live state of the path without following a symbolic link at the
# path. The result includes the SHA-256 of a regular file.
sub observe_file {
    my ($path) = @_;

    my @stat = lstat($path);
    if (!@stat) {
        die "cannot read $path: $!\n" if $! != ENOENT;
        return { path => $path, present => 0 };
    }
    my $observation = {
        path => $path,
        present => 1,
        regular => S_ISREG($stat[2]) ? 1 : 0,
        directory => S_ISDIR($stat[2]) ? 1 : 0,
        size => $stat[7],
        mode => sprintf('%04o', S_IMODE($stat[2])),
        uid => $stat[4],
        gid => $stat[5],
        inode => $stat[1],
    };
    my $owner = getpwuid($stat[4]);
    my $group = getgrgid($stat[5]);
    $observation->{owner} = $owner if defined($owner);
    $observation->{group} = $group if defined($group);
    $observation->{sha256} = $sha256_file->($path) if $observation->{regular};
    return $observation;
}

my $content_matches = sub {
    my ($observation, $expected) = @_;

    return 0 if !$observation->{present} || !$observation->{regular};
    return 0 if $observation->{sha256} ne $expected->{sha256};
    return 0 if $observation->{size} != $expected->{size};
    return 1;
};

my $metadata_matches = sub {
    my ($observation, $expected) = @_;

    return 0 if !$observation->{present};
    return 0 if $observation->{mode} ne $expected->{mode};
    return 0 if !defined($expected->{uid}) || $observation->{uid} != $expected->{uid};
    return 0 if !defined($expected->{gid}) || $observation->{gid} != $expected->{gid};
    return 1;
};

my $observation_matches = sub {
    my ($observation, $expected) = @_;

    return $content_matches->($observation, $expected)
        && $metadata_matches->($observation, $expected) ? 1 : 0;
};

my $directory_matches = sub {
    my ($observation, $expected) = @_;

    return $observation->{present}
        && $observation->{directory}
        && $metadata_matches->($observation, $expected) ? 1 : 0;
};

# The function checks an inspect-only parent directory and never changes it. The directory
# must exist. With mode, owner, and group in the policy, it must have exactly these values.
# Without them, it must belong to root. The group and other users cannot write to it.
my $check_parent_directory = sub {
    my ($entry) = @_;

    my $path = $entry->{path};
    my @stat = lstat($path);
    die "the inspect-only parent directory $path does not exist\n" if !@stat;
    die "the inspect-only parent directory $path is not a directory\n" if !S_ISDIR($stat[2]);
    if (defined($entry->{mode})) {
        my ($uid, $gid) = $account_ids->($entry->{owner}, $entry->{group});
        my $mode = sprintf('%04o', S_IMODE($stat[2]));
        die "the inspect-only parent directory $path has mode $mode, owner $stat[4], and"
            . " group $stat[5], and the policy requires $entry->{mode}, $uid, and $gid\n"
            if $mode ne $entry->{mode} || $stat[4] != $uid || $stat[5] != $gid;
        return;
    }
    die "the inspect-only parent directory $path must belong to root\n" if $stat[4] != 0;
    die "the group or other users can write to the inspect-only parent directory $path\n"
        if $stat[2] & 022;
};

# Each existing parent of the path must be a directory. A parent that the manifest lists as an
# owned directory may be missing, and the policy sets its owner and mode. The function checks
# a parent that the policy lists as inspect-only against the policy. Every other parent must
# exist and belong to root. The group and other users cannot write to it.
my $check_ancestors = sub {
    my ($path, $declared, $parents) = @_;

    my $current = '';
    for my $component (split(m{/}, substr(dirname($path), 1))) {
        $current .= "/$component";
        my @stat = lstat($current);
        if ($declared->{$current}) {
            die "the parent directory $current of $path is not a directory\n"
                if @stat && !S_ISDIR($stat[2]);
            next;
        }
        if ($parents->{$current}) {
            $check_parent_directory->($parents->{$current});
            next;
        }
        die "the parent directory $current of $path does not exist\n" if !@stat;
        die "the parent directory $current of $path is not a directory\n" if !S_ISDIR($stat[2]);
        die "the parent directory $current of $path must belong to root\n" if $stat[4] != 0;
        die "the parent directory $current of $path must not be writable by the group or"
            . " other users\n"
            if $stat[2] & 022;
    }
};

my $read_installed = sub {
    my ($target) = @_;

    my $path = $installed_path->($target);
    return undef if !-e $path;
    my $installed = $decode_json_file->($path, $RECORD_MAX_BYTES);
    die "$path is not valid\n"
        if ref($installed) ne 'HASH' || ref($installed->{files}) ne 'ARRAY';
    return $installed;
};

my $write_journal = sub {
    my ($target, $journal) = @_;

    $write_file_atomic->($journal_path->($target), $json->encode($journal), $STATE_FILE_MODE);
};

my $sibling_name = sub {
    my ($path, $kind) = @_;

    return dirname($path) . '/.' . basename($path) . ".pve-overlay-$kind-" . $random_hex->();
};

# Each journal entry contains a destination path and may contain a temporary file path and a
# backup file path. The function checks each path again because it reads them from a file.
my $journal_sibling = sub {
    my ($path, $sibling, $kind) = @_;

    return undef if !defined($sibling);
    my $prefix = dirname($path) . '/.' . basename($path) . ".pve-overlay-$kind-";
    die "the journal contains the unexpected $kind file '$sibling'\n"
        if index($sibling, $prefix) != 0
        || substr($sibling, length($prefix)) !~ m/\A[0-9a-f]+\z/;
    return $check_destination->($sibling, "journal $kind file");
};

my $finish_journal = sub {
    my ($target, $journal) = @_;

    for my $entry (@{ $journal->{files} }) {
        my $path = $check_destination->($entry->{path}, 'journal path');
        my $temporary = $journal_sibling->($path, $entry->{temporary}, 'new');
        my $backup = $journal_sibling->($path, $entry->{backup}, 'backup');
        $remove_path->($temporary) if defined($temporary);
        $remove_path->($backup) if defined($backup);
    }
    $remove_path->($journal_path->($target));
    $sync_dir->($target_dir->($target));
};

# The function restores the owner and the mode of an existing directory that the journal lists.
# It restores only a value that this transaction changed, and only while the directory still
# has the value that this transaction set.
my $restore_directory = sub {
    my ($entry, $directory) = @_;

    my @stat = lstat($directory);
    return if !@stat || !S_ISDIR($stat[2]);
    if (defined($entry->{previous_uid})) {
        my $uid = $untaint->($entry->{previous_uid}, qr/[0-9]+/, 'journal uid');
        my $gid = $untaint->($entry->{previous_gid}, qr/[0-9]+/, 'journal gid');
        my $set_uid = $untaint->($entry->{set_uid}, qr/[0-9]+/, 'journal uid');
        my $set_gid = $untaint->($entry->{set_gid}, qr/[0-9]+/, 'journal gid');
        if ($stat[4] == $set_uid && $stat[5] == $set_gid) {
            chown($uid, $gid, $directory) or die "cannot restore the owner of $directory: $!\n";
            print "recovery restored the owner of the directory $directory\n";
        } else {
            print "recovery kept the owner of the directory $directory because it differs from"
                . " the owner that this transaction set\n";
        }
    }
    if (defined($entry->{previous_mode})) {
        my $mode = $untaint->($entry->{previous_mode}, qr/[0-7]{4}/, 'journal mode');
        my $set_mode = $untaint->($entry->{set_mode}, qr/[0-7]{4}/, 'journal mode');
        my @current = lstat($directory);
        if (@current && sprintf('%04o', S_IMODE($current[2])) eq $set_mode) {
            chmod(oct($mode), $directory) or die "cannot restore the mode of $directory: $!\n";
            print "recovery restored the mode of the directory $directory\n";
        } else {
            print "recovery kept the mode of the directory $directory because it differs from"
                . " the mode that this transaction set\n";
        }
    }
};

# The function completes or reverts the transaction of an incomplete journal. For a journal
# in the committed phase, the function writes the installed record. For a journal in another
# phase, the function restores each listed destination to its state before the transaction.
# The caller acquires the target lock before calling this function. The function returns 1
# when a journal existed.
sub recover {
    my ($target) = @_;

    my $journal = $read_journal->($target);
    return 0 if !$journal;

    my $upid = $journal->{upid} // 'an unknown task';
    if ($journal->{phase} eq 'committed') {
        print "completing the committed transaction of $upid\n";
        $write_file_atomic->(
            $installed_path->($target), $json->encode($journal->{installed}), $STATE_FILE_MODE,
        );
        $finish_journal->($target, $journal);
        return 1;
    }

    print "restoring the files of the interrupted transaction of $upid\n";
    my $replacing = $journal->{phase} eq 'replacing';
    my $changed_dirs = {};
    for my $entry (reverse @{ $journal->{files} }) {
        my $destination = $check_destination->($entry->{path}, 'journal path');
        my $temporary = $journal_sibling->($destination, $entry->{temporary}, 'new');
        my $backup = $journal_sibling->($destination, $entry->{backup}, 'backup');
        $remove_path->($temporary) if defined($temporary);
        if (defined($backup) && lstat($backup)) {
            rename($backup, $destination)
                or die "cannot restore $destination from $backup: $!\n";
            # rename does not change anything when the backup and the destination are links
            # to the same file, and the backup then still exists.
            $remove_path->($backup);
            print "restored $destination\n";
        } elsif ($replacing && $entry->{action} eq 'replace' && !$entry->{previous}) {
            my $observation = observe_file($destination);
            if ($observation->{present} && ($observation->{sha256} // '') eq $entry->{sha256}) {
                $remove_path->($destination);
                print "deleted $destination, which did not exist before the transaction\n";
            }
        }
        $changed_dirs->{ dirname($destination) } = 1;
    }

    for my $entry (reverse @{ $journal->{directories} }) {
        my $directory = $check_destination->($entry->{path}, 'journal directory');
        if ($entry->{created}) {
            if (rmdir($directory)) {
                print "deleted the directory $directory\n";
            } elsif ($! == ENOTEMPTY) {
                print "kept the directory $directory, which is not empty\n";
            } elsif ($! != ENOENT) {
                die "cannot delete the directory $directory: $!\n";
            }
        } else {
            $restore_directory->($entry, $directory);
        }
        $changed_dirs->{ dirname($directory) } = 1;
    }

    for my $directory (sort keys %$changed_dirs) {
        $sync_dir->($directory) if -d $directory;
    }
    $remove_path->($journal_path->($target));
    $sync_dir->($target_dir->($target));
    return 1;
}

my $journal_copy = sub {
    my ($entries) = @_;

    my $copies = [];
    for my $entry (@$entries) {
        push @$copies, { map { $_ => $entry->{$_} } grep { $_ ne 'desired' } keys %$entry };
    }
    return $copies;
};

# The function plans changes only for the directories that the policy lets this target own.
# It checks each inspect-only parent that the manifest lists and does not plan a change for it.
my $plan_directories = sub {
    my ($policy, $validated) = @_;

    for my $path (sort keys %{ $validated->{inspected} }) {
        $check_parent_directory->($policy->{parents}->{$path});
    }
    my $directories = [];
    my $declared = { map { $_ => 1 } keys %{ $validated->{directories} } };
    for my $path (sort keys %{ $validated->{directories} }) {
        my $desired = $validated->{directories}->{$path};
        my @stat = lstat($path);
        if (!@stat) {
            die "cannot read $path: $!\n" if $! != ENOENT;
            push @$directories, { path => $path, created => 1, desired => $desired };
            next;
        }
        die "$path is not a directory\n" if !S_ISDIR($stat[2]);
        my $entry = { path => $path, desired => $desired };
        if ($stat[4] != $desired->{uid} || $stat[5] != $desired->{gid}) {
            $entry->{previous_uid} = $stat[4];
            $entry->{previous_gid} = $stat[5];
            $entry->{set_uid} = $desired->{uid};
            $entry->{set_gid} = $desired->{gid};
        }
        my $mode = sprintf('%04o', S_IMODE($stat[2]));
        if ($mode ne $desired->{mode}) {
            $entry->{previous_mode} = $mode;
            $entry->{set_mode} = $desired->{mode};
        }
        next if !defined($entry->{previous_uid}) && !defined($entry->{previous_mode});
        push @$directories, $entry;
    }
    for my $entry (@$directories) {
        $check_ancestors->($entry->{path}, $declared, $policy->{parents});
    }
    return ($directories, $declared);
};

# The function returns the file actions and the installed file records. A file that matches
# the manifest keeps its earlier write_id. Every changed file gets the UPID of this task as
# its write_id.
my $plan_files = sub {
    my ($policy, $validated, $previous_files, $declared, $upid) = @_;

    my $files = [];
    my $records = [];
    for my $path (sort keys %{ $validated->{files} }) {
        my $desired = $validated->{files}->{$path};
        $check_ancestors->($path, $declared, $policy->{parents});
        my $observation = observe_file($path);
        die "$path exists and is not a regular file\n"
            if $observation->{present} && !$observation->{regular};
        my $write_id = $upid;
        if ($observation_matches->($observation, $desired)) {
            $write_id = $previous_files->{$path}->{write_id} // $upid
                if $previous_files->{$path};
        } else {
            push @$files, {
                path => $path,
                action => 'replace',
                member => $desired->{member},
                sha256 => $desired->{sha256},
                previous => $observation->{present},
                temporary => $sibling_name->($path, 'new'),
                backup => $observation->{present} ? $sibling_name->($path, 'backup') : undef,
                desired => $desired,
            };
        }
        push @$records, {
            (map { $_ => $desired->{$_} } qw(path sha256 size mode owner group uid gid)),
            write_id => $write_id,
        };
    }

    for my $path (sort keys %$previous_files) {
        next if $validated->{files}->{$path};
        if (!$policy->{files}->{$path}) {
            print "kept $path because the policy does not list it\n";
            next;
        }
        my $observation = observe_file($path);
        next if !$observation->{present};
        die "$path exists and is not a regular file\n" if !$observation->{regular};
        $check_ancestors->($path, $declared, $policy->{parents});
        push @$files, {
            path => $path,
            action => 'remove',
            previous => 1,
            backup => $sibling_name->($path, 'backup'),
        };
    }
    return ($files, $records);
};

my $prepare_files = sub {
    my ($directories, $files, $archive_path) = @_;

    for my $entry (@$directories) {
        my $desired = $entry->{desired};
        if ($entry->{created}) {
            mkdir($entry->{path}, $STATE_DIR_MODE)
                or die "cannot create the directory $entry->{path}: $!\n";
        }
        if ($entry->{created} || defined($entry->{previous_uid})) {
            chown($desired->{uid}, $desired->{gid}, $entry->{path})
                or die "cannot change the owner of $entry->{path}: $!\n";
        }
        if ($entry->{created} || defined($entry->{previous_mode})) {
            chmod(oct($desired->{mode}), $entry->{path})
                or die "cannot change the mode of $entry->{path}: $!\n";
        }
        $sync_dir->(dirname($entry->{path}));
        print "prepared the directory $entry->{path}\n";
    }

    my $by_member = {};
    my $handles = {};
    for my $entry (grep { $_->{action} eq 'replace' } @$files) {
        sysopen(
            my $handle,
            $entry->{temporary},
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW,
            $STATE_FILE_MODE,
        ) or die "cannot create $entry->{temporary}: $!\n";
        $handles->{ $entry->{member} } = $handle;
        $by_member->{ $entry->{member} } = $entry;
    }
    scan_archive(
        $archive_path,
        sub {
            my ($member) = @_;
            my $entry = $by_member->{ $member->{name} } or return undef;
            my $handle = $handles->{ $member->{name} };
            return sub { $write_all->($handle, $_[0], $entry->{temporary}) };
        },
    );
    for my $member (sort keys %$by_member) {
        my $entry = $by_member->{$member};
        my $handle = $handles->{$member};
        my $desired = $entry->{desired};
        $handle->sync() or die "cannot sync $entry->{temporary}: $!\n";
        chown($desired->{uid}, $desired->{gid}, $handle)
            or die "cannot change the owner of $entry->{temporary}: $!\n";
        chmod(oct($desired->{mode}), $handle)
            or die "cannot change the mode of $entry->{temporary}: $!\n";
        close($handle) or die "cannot close $entry->{temporary}: $!\n";
        my $written_sha256 = $sha256_file->($entry->{temporary});
        die "$entry->{temporary} has SHA-256 $written_sha256 after the write, and the archive"
            . " member has $desired->{sha256}\n"
            if $written_sha256 ne $desired->{sha256};
    }
};

my $replace_files = sub {
    my ($files) = @_;

    for my $entry (@$files) {
        my $path = $entry->{path};
        if (defined($entry->{backup})) {
            link($path, $entry->{backup}) or die "cannot link $path to $entry->{backup}: $!\n";
        }
        if ($entry->{action} eq 'replace') {
            rename($entry->{temporary}, $path)
                or die "cannot rename $entry->{temporary} to $path: $!\n";
            print "wrote $path\n";
        } else {
            unlink($path) or die "cannot delete $path: $!\n";
            print "deleted $path\n";
        }
        $sync_dir->(dirname($path));
    }
};

# The function plans and runs the file transaction of a validated archive. The caller acquires
# the target lock and runs recover before calling this function.
my $apply_archive = sub {
    my ($policy, $request, $archive_path, $validated, $upid, $user) = @_;

    my $target = $policy->{target};
    my $previous = $read_installed->($target);
    my $previous_files = {};
    for my $entry (@{ $previous ? $previous->{files} : [] }) {
        $previous_files->{ $check_destination->($entry->{path}, 'installed path') } = $entry;
    }

    my ($directories, $declared) = $plan_directories->($policy, $validated);
    my ($files, $records) =
        $plan_files->($policy, $validated, $previous_files, $declared, $upid);

    my $installed = {
        workspace => $policy->{workspace},
        node => $policy->{node},
        environment => $policy->{environment},
        release_tag => $request->{release_tag},
        asset => $request->{asset},
        sha256 => $request->{sha256},
        source_revision => $request->{source_revision},
        manifest_sha256 => $validated->{manifest_sha256},
        upid => $upid,
        user => $user,
        installed_at => strftime('%Y-%m-%dT%H:%M:%SZ', gmtime()),
        directories => [
            map {
                my $entry = $validated->{directories}->{$_};
                +{ map { $_ => $entry->{$_} } qw(path mode owner group uid gid) }
            } sort keys %{ $validated->{directories} }
        ],
        files => $records,
    };

    if (!@$files && !@$directories) {
        $write_file_atomic->(
            $installed_path->($target), $json->encode($installed), $STATE_FILE_MODE,
        );
        print "every file matches the archive, and the task wrote only the installed record\n";
        return $installed;
    }

    my $journal = {
        phase => 'preparing',
        upid => $upid,
        archive_stage => $request->{archive_stage},
        bundle_stage => $request->{bundle_stage},
        directories => $journal_copy->($directories),
        files => $journal_copy->($files),
    };
    eval {
        $write_journal->($target, $journal);
        $prepare_files->($directories, $files, $archive_path);
        $journal->{phase} = 'replacing';
        $write_journal->($target, $journal);
        $replace_files->($files);
        $journal->{phase} = 'committed';
        $journal->{installed} = $installed;
        $write_journal->($target, $journal);
        $write_file_atomic->(
            $installed_path->($target), $json->encode($installed), $STATE_FILE_MODE,
        );
        $finish_journal->($target, $journal);
    };
    if (my $error = $@) {
        print "the transaction failed: $error";
        eval { recover($target) };
        die "${error}restoring the files of the transaction also failed: $@" if $@;
        die $error;
    }
    return $installed;
};

# The function restores an incomplete journal, validates an archive that verify_attestation
# accepted, and installs its files. The caller acquires the target lock before calling it.
sub install_verified_archive {
    my ($policy, $request, $archive_path, $upid, $user) = @_;

    check_node($policy);
    $ensure_target_dir->($policy->{target});
    recover($policy->{target});
    my $validated = validate_archive($policy, $request, $archive_path);
    return $apply_archive->($policy, $request, $archive_path, $validated, $upid, $user);
}

# The function checks the install parameters before the API starts a worker.
sub check_install_request {
    my ($target, $user, $param) = @_;

    my $policy = load_policy($target);
    check_node($policy);
    die "the trusted root $TRUSTED_ROOT_FILE does not exist\n" if !-e $TRUSTED_ROOT_FILE;
    my $request = {
        release_tag => $untaint->($param->{'release-tag'}, $NAME_RE, 'release-tag'),
        asset => $untaint->($param->{asset}, $NAME_RE, 'asset'),
        sha256 => $untaint->($param->{sha256}, $SHA256_RE, 'sha256'),
        source_revision =>
            $untaint->($param->{'source-revision'}, $REVISION_RE, 'source-revision'),
        archive_stage => $untaint->($param->{'archive-stage'}, $STAGE_RE, 'archive-stage'),
        bundle_stage => $untaint->($param->{'bundle-stage'}, $STAGE_RE, 'bundle-stage'),
    };
    check_stage($policy->{target}, $request->{archive_stage}, $user, 'archive');
    check_stage($policy->{target}, $request->{bundle_stage}, $user, 'bundle');
    return $request;
}

# The function runs one install in a task worker. The worker verifies the staged archive with
# gh, validates and installs it, and deletes the two stages.
sub install {
    my ($target, $request, $upid, $user) = @_;

    my $policy = load_policy($target);
    check_node($policy);
    return with_target_lock(
        $policy->{target},
        sub {
            my $archive =
                check_stage($policy->{target}, $request->{archive_stage}, $user, 'archive');
            my $bundle =
                check_stage($policy->{target}, $request->{bundle_stage}, $user, 'bundle');
            verify_attestation($policy, $request, $archive->{data_path}, $bundle->{data_path});
            print "gh attestation verify accepted $request->{asset} with SHA-256"
                . " $request->{sha256}\n";
            my $installed = install_verified_archive(
                $policy, $request, $archive->{data_path}, $upid, $user,
            );
            $remove_stage->($archive);
            $remove_stage->($bundle);
            return $installed;
        },
    );
}

my $secrets_path = sub {
    my ($target) = @_;

    return $target_dir->($target) . '/secrets.json';
};

# The secret record of a target maps each field to its version, the SHA-256 of the storage
# file content, the consumer units that still need a restart, and the temporary file of an
# unfinished write.
my $read_secrets = sub {
    my ($target) = @_;

    my $path = $secrets_path->($target);
    return { fields => {} } if !-e $path;
    my $secrets = $decode_json_file->($path, $RECORD_MAX_BYTES);
    die "$path is not valid\n"
        if ref($secrets) ne 'HASH' || ref($secrets->{fields}) ne 'HASH';
    return $secrets;
};

my $write_secrets = sub {
    my ($target, $secrets) = @_;

    $write_file_atomic->($secrets_path->($target), $json->encode($secrets), $STATE_FILE_MODE);
};

my $secret_states = sub {
    my ($policy) = @_;

    my $secrets = $read_secrets->($policy->{target});
    my $states = [];
    for my $name (sort keys %{ $policy->{secret_fields} }) {
        my $descriptor = $policy->{secret_fields}->{$name};
        my $observation = observe_file($descriptor->{path});
        # configured is true when the storage file is a regular file with the mode, owner, and
        # group of the policy. The SHA-256 represents the content of a regular storage file.
        my $expected = {
            mode => $descriptor->{mode},
            uid => scalar(getpwnam($descriptor->{owner})),
            gid => scalar(getgrnam($descriptor->{group})),
        };
        my $configured = $observation->{present}
            && $observation->{regular}
            && $metadata_matches->($observation, $expected) ? 1 : 0;
        my $state = { field => $name, configured => $configured };
        $state->{sha256} = $observation->{sha256} if defined($observation->{sha256});
        my $record = $secrets->{fields}->{$name};
        $state->{version} = $record->{version} if $record;
        push @$states, $state;
    }
    return $states;
};

# The function checks a secret value against its policy field. The messages do not contain
# the value.
my $check_secret_value = sub {
    my ($descriptor, $value) = @_;

    my $name = $descriptor->{name};
    die "the value of $name is missing\n" if !defined($value) || ref($value);
    die "the value of $name is shorter than $descriptor->{min_length} or longer than"
        . " $descriptor->{max_length} characters\n"
        if length($value) < $descriptor->{min_length}
        || length($value) > $descriptor->{max_length};
    die "the value of $name contains a control character\n" if $value =~ m/[\x00-\x1f\x7f]/;
    die "the value of $name does not match the pattern of the policy\n"
        if $value !~ $descriptor->{pattern};
};

my $secret_descriptor = sub {
    my ($policy, $field) = @_;

    $field = $untaint->($field, $SECRET_FIELD_RE, 'field');
    my $descriptor = $policy->{secret_fields}->{$field};
    die "the policy of this target does not list the secret field $field\n" if !$descriptor;
    return $descriptor;
};

# The function checks a secret request before the API starts a worker. The returned request
# does not contain the value.
sub check_secret_request {
    my ($target, $field, $value, $version) = @_;

    my $policy = load_policy($target);
    check_node($policy);
    my $descriptor = $secret_descriptor->($policy, $field);
    $check_secret_value->($descriptor, $value);
    return {
        target => $policy->{target},
        field => $descriptor->{name},
        version => $untaint->($version, $VERSION_RE, 'version') + 0,
    };
}

my $run_systemctl = sub {
    my (@arguments) = @_;

    my $output = '';
    my $errors = '';
    eval {
        PVE::Tools::run_command(
            [$SYSTEMCTL_COMMAND, @arguments],
            outfunc => sub { $output .= shift() . "\n" },
            errfunc => sub { $errors .= shift() . "\n" },
            timeout => $UNIT_TIMEOUT_SECONDS,
        );
    };
    if (my $failure = $@) {
        $errors = substr($errors, 0, $UNIT_STDERR_LIMIT);
        $errors =~ s/\s+\z//;
        $failure =~ s/\s+\z//;
        die "systemctl @arguments failed: $failure: $errors\n";
    }
    return $output;
};

my $unit_state = sub {
    my ($unit) = @_;

    my $state = $run_systemctl->('show', '--property=ActiveState', '--value', $unit);
    $state =~ s/\s+\z//;
    return $state;
};

my $write_secret_file = sub {
    my ($descriptor, $content, $temporary) = @_;

    my $path = $descriptor->{path};
    my ($uid, $gid) = $account_ids->($descriptor->{owner}, $descriptor->{group});
    sysopen(my $handle, $temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, $STATE_FILE_MODE)
        or die "cannot create $temporary: $!\n";
    $write_all->($handle, $content, $temporary);
    chown($uid, $gid, $handle) or die "cannot change the owner of $temporary: $!\n";
    chmod(oct($descriptor->{mode}), $handle) or die "cannot change the mode of $temporary: $!\n";
    $handle->sync() or die "cannot sync $temporary: $!\n";
    close($handle) or die "cannot close $temporary: $!\n";
    rename($temporary, $path) or die "cannot rename $temporary to $path: $!\n";
    $sync_dir->(dirname($path));
};

# The function sets the mode, owner, and group of the policy on the existing storage file and
# does not change its content.
my $repair_secret_metadata = sub {
    my ($descriptor, $uid, $gid) = @_;

    my $path = $descriptor->{path};
    sysopen(my $handle, $path, O_RDONLY | O_NOFOLLOW) or die "cannot open $path: $!\n";
    my @stat = stat($handle);
    die "$path does not identify a regular file\n" if !S_ISREG($stat[2]);
    chown($uid, $gid, $handle) or die "cannot change the owner of $path: $!\n";
    chmod(oct($descriptor->{mode}), $handle) or die "cannot change the mode of $path: $!\n";
    $handle->sync() or die "cannot sync $path: $!\n";
    close($handle) or die "cannot close $path: $!\n";
};

# The function sets one secret field in a task worker. A lower version fails. The same version
# with another value fails. When the version and value match the record, the storage file
# matches, and the record does not list a consumer restart, the task does not change anything.
# Otherwise, the task records the version first. When the content differs, the task records a
# restart for each consumer unit that is running and writes the storage file. When only the
# mode, owner, or group differs, the task changes them on the existing file and does not record
# a restart. The task then restarts each recorded unit that is running or failed.
# It removes a recorded unit that is inactive, deactivating, or in maintenance from the record
# without starting it. The record retains a failed restart. The next accepted request for the
# field checks the state of the unit.
sub set_secret {
    my ($target, $field, $value, $version, $upid) = @_;

    my $policy = load_policy($target);
    check_node($policy);
    my $descriptor = $secret_descriptor->($policy, $field);
    $check_secret_value->($descriptor, $value);
    $version = $untaint->($version, $VERSION_RE, 'version') + 0;
    my $name = $descriptor->{name};
    my $path = $descriptor->{path};

    return with_target_lock(
        $policy->{target},
        sub {
            $ensure_target_dir->($policy->{target});
            recover($policy->{target});
            my $secrets = $read_secrets->($policy->{target});
            my $record = $secrets->{fields}->{$name};

            if ($record && defined($record->{temporary})) {
                my $temporary = $journal_sibling->($path, $record->{temporary}, 'new');
                $remove_path->($temporary);
            }

            my $content = encode_utf8("$name=$value\n");
            my $sha256 = Digest::SHA::sha256_hex($content);
            if ($record) {
                die "version $version of $name is lower than the stored version"
                    . " $record->{version}\n"
                    if $version < $record->{version};
                die "version $version of $name already has another value\n"
                    if $version == $record->{version} && $record->{sha256} ne $sha256;
            }

            my ($uid, $gid) = $account_ids->($descriptor->{owner}, $descriptor->{group});
            my $observation = observe_file($path);
            die "$path exists and is not a regular file\n"
                if $observation->{present} && !$observation->{regular};
            my $expected = {
                sha256 => $sha256,
                size => length($content),
                mode => $descriptor->{mode},
                uid => $uid,
                gid => $gid,
            };
            my $same_content = $content_matches->($observation, $expected);
            my $same_metadata = $same_content && $metadata_matches->($observation, $expected);

            # A recorded restart counts only for a unit that the policy still lists.
            my $declared = { map { $_ => 1 } @{ $descriptor->{consumer_units} } };
            my $pending = {};
            for my $unit (@{ $record ? $record->{pending} // [] : [] }) {
                my $checked = $untaint->($unit, $UNIT_RE, 'recorded consumer unit');
                $pending->{$checked} = 1 if $declared->{$checked};
            }
            # The task records new restarts only when the content changes. A metadata repair
            # keeps the restarts that an earlier failed or stopped task recorded.
            if (!$same_content) {
                for my $unit (@{ $descriptor->{consumer_units} }) {
                    if ($RUNNING_STATES->{ $unit_state->($unit) }) {
                        $pending->{$unit} = 1;
                    } else {
                        print "the consumer unit $unit is not running, and the task does not"
                            . " start it\n";
                    }
                }
            }
            my $next = {
                version => $version,
                sha256 => $sha256,
                pending => [sort keys %$pending],
            };

            if ($same_metadata && !%$pending && $record && $record->{version} == $version) {
                print "the secret field $name already has version $version, and the task did"
                    . " not change a file or a unit\n";
                return;
            }

            if (!$same_metadata) {
                $check_ancestors->($path, $policy->{directories}, $policy->{parents});
                die "the parent directory of $path does not exist\n" if !-d dirname($path);
            }
            $next->{temporary} = $sibling_name->($path, 'new') if !$same_content;
            $secrets->{fields}->{$name} = $next;
            $write_secrets->($policy->{target}, $secrets);

            if (!$same_content) {
                $write_secret_file->($descriptor, $content, $next->{temporary});
                delete $next->{temporary};
                $write_secrets->($policy->{target}, $secrets);
                print "the task wrote version $version of the secret field $name to $path\n";
            } elsif (!$same_metadata) {
                $repair_secret_metadata->($descriptor, $uid, $gid);
                print "the task restored the mode, owner, and group of $path\n";
            }

            for my $unit (sort keys %$pending) {
                my $state = $unit_state->($unit);
                if ($RESTART_STATES->{$state}) {
                    $run_systemctl->('restart', $unit);
                    print "the task restarted the consumer unit $unit\n";
                } else {
                    print "the consumer unit $unit is $state, and the task does not start it\n";
                }
                $next->{pending} = [grep { $_ ne $unit } @{ $next->{pending} }];
                $write_secrets->($policy->{target}, $secrets);
            }
        },
    );
}

# The function returns the policy identity, the installed record, and the live state of each
# installed file and owned directory. Without an installed record, the files and directories
# are those of the policy. The function does not change a file.
sub read_state {
    my ($target) = @_;

    my $policy = load_policy($target);
    check_node($policy);
    my $installed = $read_installed->($policy->{target});
    my $state = 'none';
    $state = 'committed' if $installed;
    $state = 'interrupted' if -e $journal_path->($policy->{target});

    my $expected_files = [map { { path => $_ } } sort keys %{ $policy->{files} }];
    $expected_files = $installed->{files} if $installed;

    my $files = [];
    my $observed = '';
    for my $expected (sort { $a->{path} cmp $b->{path} } @$expected_files) {
        my $path = $check_destination->($expected->{path}, 'installed path');
        my $observation = observe_file($path);
        my $file = { path => $path, present => $observation->{present} };
        for my $key (qw(sha256 size mode owner group uid gid)) {
            $file->{$key} = $observation->{$key} if defined($observation->{$key});
        }
        if ($installed) {
            $file->{write_id} = $expected->{write_id};
            $file->{matches} = $observation_matches->($observation, $expected);
        }
        push @$files, $file;
        my @fields = ($path, @$observation{qw(present sha256 size mode uid gid)});
        $observed .= join("\0", map { $_ // '' } @fields) . "\n";
    }

    # The function returns the owned directories of the installed record, or the owned
    # directories of the policy without a record. It does not include inspect-only parents.
    my $expected_directories = [values %{ $policy->{directories} }];
    $expected_directories = $installed->{directories} // [] if $installed;
    my $directories = [];
    for my $expected (sort { $a->{path} cmp $b->{path} } @$expected_directories) {
        my $path = $check_destination->($expected->{path}, 'installed directory');
        my $observation = observe_file($path);
        my $directory = { path => $path, present => $observation->{present} };
        for my $key (qw(mode owner group uid gid)) {
            $directory->{$key} = $observation->{$key} if defined($observation->{$key});
        }
        $directory->{matches} = $directory_matches->($observation, $expected) if $installed;
        push @$directories, $directory;
        my @fields = ($path, @$observation{qw(present directory mode uid gid)});
        $observed .= join("\0", 'directory', map { $_ // '' } @fields) . "\n";
    }

    my $installed_fields = undef;
    $installed_fields = { map { $_ => $installed->{$_} } @$INSTALLED_KEYS } if $installed;
    return {
        workspace => $policy->{workspace},
        node => $policy->{node},
        environment => $policy->{environment},
        state => $state,
        installed => $installed_fields,
        files => $files,
        directories => $directories,
        observed_sha256 => Digest::SHA::sha256_hex($observed),
        secrets => $secret_states->($policy),
    };
}

1;
