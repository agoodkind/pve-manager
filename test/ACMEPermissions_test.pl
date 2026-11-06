#!/usr/bin/perl -T

use strict;
use warnings;

use lib qw(.. .);

use PVE::API2::ACME;
use PVE::RPCEnvironment;
use Test::More;

delete @ENV{qw(PATH IFS CDPATH ENV BASH_ENV)};
my $rpcenv = PVE::RPCEnvironment->init('priv');
$rpcenv->init_request(userconfig => 'acme-permissions-test.cfg');

my @methods = qw(new_certificate renew_certificate revoke_certificate);
my @users = (
    ['stock@pve', [1, 1, 1]],
    ['stock-node@pve', [0, 0, 0]],
    ['stock-inherited@pve', [1, 1, 1]],
    ['order@pve', [1, 0, 0]],
    ['renew@pve', [0, 1, 0]],
    ['revoke@pve', [0, 0, 1]],
    ['reference@pve', [1, 1, 1]],
    ['child@pve', [0, 0, 0]],
    ['other@pve', [0, 0, 0]],
    ['denied@pve', [0, 0, 0]],
);
for my $index (0 .. $#methods) {
    my $name = $methods[$index];
    my @registered = grep { $_->{name} eq $name } @{PVE::API2::ACME->method_attributes()};
    die "expected exactly one registered $name method\n" unless @registered == 1;
    for my $case (@users) {
        my ($user, $expected) = @$case;
        my $allowed = eval {
            $rpcenv->check_api2_permissions($registered[0]->{permissions}, $user, { node => 'localhost' });
            1;
        };
        my $error = $@;
        if ($expected->[$index]) {
            ok($allowed, "$user can authorize $name") or diag("$error");
        } else {
            ok(!$allowed && "$error" =~ /permission check failed/i,
                "$user cannot authorize $name") or diag("$error");
        }
    }
}
done_testing();
