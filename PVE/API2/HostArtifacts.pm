package PVE::API2::HostArtifacts;

use strict;
use warnings;

use POSIX qw(SIGCHLD SIG_BLOCK SIG_UNBLOCK SIG_SETMASK sigprocmask);

use PVE::HostArtifacts;
use PVE::JSONSchema qw(get_standard_option);
use PVE::RPCEnvironment;
use PVE::Tools qw(extract_param);

use base qw(PVE::RESTHandler);

# pve-http-server rejects a request body above 512 KiB ($limit_max_post in
# PVE/APIServer/AnyEvent.pm). A form-encoded body expands each of '+', '/', and '=' to three
# bytes. The worst case body of a 128 KiB base64 value is 384 KiB.
my $CHUNK_BASE64_MAX_LENGTH = 128 * 1024;
my $NAME_MAX_LENGTH = 255;
my $SECRET_VALUE_MAX_LENGTH = 512;
my $PROGRAM_NAME_PATTERN = '[a-z][a-z0-9-]*';
my $PROGRAM_STAGE_PATTERN = "$PROGRAM_NAME_PATTERN=[0-9a-f]{32}:[0-9a-f]{32}";

my $target_property = {
    type => 'string',
    pattern => '[0-9a-f]{64}',
    description => 'The target is the lowercase hexadecimal SHA-256 of the UTF-8 bytes of'
        . ' the workspace selector.',
};

my $stage_property = {
    type => 'string',
    pattern => '[0-9a-f]{32}',
    description => 'The stage method returns this stage identifier.',
};

my $name_property = sub {
    my ($description) = @_;

    return {
        type => 'string',
        pattern => '[A-Za-z0-9][A-Za-z0-9._-]*',
        maxLength => $NAME_MAX_LENGTH,
        description => $description,
    };
};

# rest_handler stores the authenticated user of this request in the credentials immediately
# before it calls the method. The user of the environment can belong to another request.
my $request_user = sub {
    my $rpcenv = PVE::RPCEnvironment::get();
    my $credentials = $rpcenv->get_credentials(1) // {};
    my $user = $credentials->{userid};
    die "the authenticated user of the request is not available\n" if !defined($user);
    return $user;
};

# The function starts a task worker and returns its UPID. fork_worker waits for the worker with
# a read that a SIGCHLD from an earlier worker interrupts, and then fails with "got no worker
# upid". The function blocks SIGCHLD until fork_worker returns, and the signal arrives afterwards.
my $start_worker = sub {
    my ($type, $target, $user, $code) = @_;

    my $rpcenv = PVE::RPCEnvironment::get();
    my $sigchld = POSIX::SigSet->new(SIGCHLD);
    my $previous_signals = POSIX::SigSet->new();
    sigprocmask(SIG_BLOCK, $sigchld, $previous_signals)
        or die "unable to block SIGCHLD: $!\n";
    my $upid = eval {
        $rpcenv->fork_worker(
            $type,
            $target,
            $user,
            sub {
                my ($worker_upid) = @_;
                sigprocmask(SIG_UNBLOCK, $sigchld);
                $code->($worker_upid);
            },
        );
    };
    my $fork_error = $@;
    sigprocmask(SIG_SETMASK, $previous_signals);
    die $fork_error if $fork_error;

    return $upid;
};

my $file_properties = {
    path => { type => 'string', description => 'The path is the absolute path of the file.' },
    present => { type => 'boolean', description => 'The value is set when the path exists.' },
    sha256 => {
        type => 'string',
        optional => 1,
        description => 'The value is the SHA-256 of the file. A path that is not a regular file'
            . ' does not have this field.',
    },
    size => { type => 'integer', optional => 1, description => 'The value is the size in bytes.' },
    mode => {
        type => 'string',
        optional => 1,
        description => 'The value gives the permission bits as four octal digits.',
    },
    owner => { type => 'string', optional => 1, description => 'The value is the owner name.' },
    group => { type => 'string', optional => 1, description => 'The value is the group name.' },
    uid => { type => 'integer', optional => 1, description => 'The value is the numeric owner.' },
    gid => { type => 'integer', optional => 1, description => 'The value is the numeric group.' },
    write_id => {
        type => 'string',
        optional => 1,
        description => 'The value is the UPID of the task that last wrote the file.',
    },
    matches => {
        type => 'boolean',
        optional => 1,
        description => 'The value is set when the live file equals the installed record in'
            . ' content, size, mode, owner, and group.',
    },
};

my $directory_properties = {
    path => { type => 'string', description => 'The path is the absolute path of the directory.' },
    present => { type => 'boolean', description => 'The value is true when the path exists.' },
    map { $_ => $file_properties->{$_} } qw(mode owner group uid gid),
    matches => {
        type => 'boolean',
        optional => 1,
        description => 'The value is true when the path is a directory with the mode, owner, and'
            . ' group of the installed record.',
    },
};

__PACKAGE__->register_method({
    name => 'stage_host_artifact',
    path => '{target}/stage',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    expose_credentials => 1,
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.HostArtifacts.Modify']],
    },
    description => 'The method adds one chunk of an archive or an attestation bundle to a'
        . ' stage on the node. Offset 0 creates a stage. Each later offset must equal the'
        . ' stage length.',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            target => $target_property,
            kind => {
                type => 'string',
                enum => ['archive', 'bundle', 'program', 'program-bundle'],
                description => 'The value identifies the content of the stage.',
            },
            program => {
                type => 'string',
                pattern => $PROGRAM_NAME_PATTERN,
                optional => 1,
                description => 'The value is the name of a program in the target policy. The'
                    . ' kinds program and program-bundle require it. The kinds archive and'
                    . ' bundle reject it.',
            },
            offset => {
                type => 'integer',
                minimum => 0,
                description => 'The value is the byte offset of the chunk in the stage.',
            },
            data => {
                type => 'string',
                maxLength => $CHUNK_BASE64_MAX_LENGTH,
                description => 'The value is the base64 encoded chunk.',
            },
            stage => { %$stage_property, optional => 1 },
        },
    },
    returns => {
        type => 'object',
        properties => {
            stage => $stage_property,
            length => {
                type => 'integer',
                description => 'The value is the stage length in bytes.',
            },
        },
    },
    code => sub {
        my ($param) = @_;

        my $user = $request_user->();
        return PVE::HostArtifacts::stage_chunk(
            $param->{target},
            $user,
            $param->{kind},
            $param->{offset},
            $param->{data},
            $param->{stage},
            $param->{program},
        );
    },
});

__PACKAGE__->register_method({
    name => 'install_host_artifact',
    path => '{target}',
    method => 'POST',
    protected => 1,
    proxyto => 'node',
    expose_credentials => 1,
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.HostArtifacts.Modify']],
    },
    description => 'The hostartifact task verifies a staged archive with its staged'
        . ' attestation bundle and installs its files.',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            target => $target_property,
            'release-tag' => $name_property->('The value is the release tag of the archive.'),
            asset => $name_property->('The value is the release asset name of the archive.'),
            sha256 => {
                type => 'string',
                pattern => '[0-9a-f]{64}',
                description => 'The value is the SHA-256 of the archive.',
            },
            'source-revision' => {
                type => 'string',
                pattern => '[0-9a-f]{40}',
                description => 'The value is the source revision that built the archive.',
            },
            'archive-stage' => $stage_property,
            'bundle-stage' => $stage_property,
            'program-stages' => {
                type => 'string',
                pattern => "$PROGRAM_STAGE_PATTERN(?:,$PROGRAM_STAGE_PATTERN)*",
                optional => 1,
                description => 'The value lists the stages for each program as'
                    . ' `<name>=<archive-stage>:<bundle-stage>` entries separated by commas.',
            },
        },
    },
    returns => {
        type => 'string',
        description => 'The value is the UPID of the hostartifact task.',
    },
    code => sub {
        my ($param) = @_;

        my $user = $request_user->();
        my $target = PVE::HostArtifacts::check_target($param->{target});
        my $request = PVE::HostArtifacts::check_install_request($target, $user, $param);

        return $start_worker->(
            'hostartifact',
            $target,
            $user,
            sub {
                my ($worker_upid) = @_;
                PVE::HostArtifacts::install($target, $request, $worker_upid, $user);
            },
        );
    },
});

__PACKAGE__->register_method({
    name => 'set_host_secret',
    path => '{target}/secrets/{field}',
    method => 'PUT',
    protected => 1,
    proxyto => 'node',
    expose_credentials => 1,
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.HostSecrets.Modify']],
    },
    description => 'The hostsecret task writes one secret field of a target and restarts the'
        . ' consumer units of the field when the storage file changes.',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            target => $target_property,
            field => {
                type => 'string',
                pattern => '[A-Z_][A-Z0-9_]{0,63}',
                description => 'The value is the name of a secret field in the target policy.',
            },
            value => {
                type => 'string',
                maxLength => $SECRET_VALUE_MAX_LENGTH,
                description => 'The value is the secret. Responses, errors, and task logs do'
                    . ' not contain it.',
            },
            version => {
                type => 'integer',
                minimum => 1,
                description => 'The value is the version of the secret.',
            },
        },
    },
    returns => {
        type => 'string',
        description => 'The value is the UPID of the hostsecret task.',
    },
    code => sub {
        my ($param) = @_;

        my $user = $request_user->();
        my $value = extract_param($param, 'value');
        my $request = PVE::HostArtifacts::check_secret_request(
            $param->{target}, $param->{field}, $value, $param->{version},
        );

        return $start_worker->(
            'hostsecret',
            $request->{target},
            $user,
            sub {
                my ($worker_upid) = @_;
                PVE::HostArtifacts::set_secret(
                    $request->{target},
                    $request->{field},
                    $value,
                    $request->{version},
                    $worker_upid,
                );
            },
        );
    },
});

__PACKAGE__->register_method({
    name => 'get_host_artifact',
    path => '{target}',
    method => 'GET',
    protected => 1,
    proxyto => 'node',
    permissions => {
        check => ['perm', '/nodes/{node}', ['Sys.HostArtifacts.Audit']],
    },
    description => 'The method returns the installed record of a target and the live state of'
        . ' each of its files. The method does not change a file.',
    parameters => {
        additionalProperties => 0,
        properties => {
            node => get_standard_option('pve-node'),
            target => $target_property,
        },
    },
    returns => {
        type => 'object',
        properties => {
            workspace => {
                type => 'string',
                description => 'The value is the workspace selector.',
            },
            node => {
                type => 'string',
                description => 'The value is the node in the target policy.',
            },
            environment => {
                type => 'string',
                description => 'The value is the environment in the target policy.',
            },
            state => {
                type => 'string',
                enum => ['none', 'committed', 'interrupted'],
                description => 'The value is none without an installed record and interrupted'
                    . ' while the journal of an incomplete transaction exists. Otherwise the'
                    . ' value is committed.',
            },
            installed => {
                type => 'object',
                optional => 1,
                description => 'The value is the installed record, or null without a record.',
                properties => {
                    release_tag => { type => 'string' },
                    asset => { type => 'string' },
                    sha256 => { type => 'string' },
                    source_revision => { type => 'string' },
                    manifest_sha256 => { type => 'string' },
                    upid => { type => 'string' },
                    user => { type => 'string' },
                    installed_at => { type => 'string' },
                },
            },
            files => {
                type => 'array',
                description => 'The array has one entry for each file in the installed record.'
                    . ' Without a record, the array has one entry for each file in the policy.',
                items => { type => 'object', properties => $file_properties },
            },
            directories => {
                type => 'array',
                description => 'The array has one entry for each owned directory in the installed'
                    . ' record. Without a record, the array has one entry for each owned'
                    . ' directory in the policy. The array does not include inspect-only parent'
                    . ' directories.',
                items => { type => 'object', properties => $directory_properties },
            },
            observed_sha256 => {
                type => 'string',
                description => 'The value is the SHA-256 of the path, presence, SHA-256, size,'
                    . ' mode, owner, and group of every listed file and of the path, presence,'
                    . ' type, mode, owner, and group of every listed directory.',
            },
            secrets => {
                type => 'array',
                description => 'The array has one entry for each secret field in the policy.'
                    . ' An entry does not contain the secret.',
                items => {
                    type => 'object',
                    properties => {
                        field => {
                            type => 'string',
                            description => 'The value is the name of the secret field.',
                        },
                        configured => {
                            type => 'boolean',
                            description => 'The value is true when the storage file is a regular'
                                . ' file with the mode, owner, and group of the policy.',
                        },
                        restart_pending => {
                            type => 'boolean',
                            description => 'The value is true when the secret record lists a'
                                . ' consumer restart for a unit that the policy lists.',
                        },
                        version => {
                            type => 'integer',
                            optional => 1,
                            description => 'The value is the recorded version of the field.',
                        },
                        sha256 => {
                            type => 'string',
                            optional => 1,
                            description => 'The value is the SHA-256 of the storage file.',
                        },
                    },
                },
            },
        },
    },
    code => sub {
        my ($param) = @_;

        return PVE::HostArtifacts::read_state($param->{target});
    },
});

1;
