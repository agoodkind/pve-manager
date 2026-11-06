#!/usr/bin/perl -T

use strict;
use warnings;

use lib qw(.. .);

use File::Temp qw(tempfile);
use Scalar::Util qw(tainted);
use Test::More;

use HostArtifactsInstalledSourceTest;

my ($file) = tempfile(UNLINK => 1);
print {$file} 'hostconfig_fixture.tar.gz' or die "cannot write the field fixture: $!\n";
seek($file, 0, 0) or die "cannot rewind the field fixture: $!\n";
my $value = <$file>;
ok(tainted($value), 'file input supplies a tainted field value');

for my $case (
    ['without inner captures', qr/\Ahostconfig_[a-z_]+\.tar\.gz\z/],
    ['with a full inner capture', qr/\A(hostconfig_[a-z_]+\.tar\.gz)\z/],
    ['with a partial inner capture', qr/\Ahostconfig_([a-z_]+)\.tar\.gz\z/],
    ['with nested inner captures', qr/\A(hostconfig_([a-z_]+)\.tar\.gz)\z/],
) {
    my $validated = HostArtifactsInstalledSourceTest::field({ asset => $value }, 'asset', $case->[1]);
    is($validated, $value, "the pattern $case->[0] returns the whole field");
    ok(!tainted($validated), "the pattern $case->[0] removes taint");
    eval { HostArtifactsInstalledSourceTest::field({ asset => "$value.invalid" }, 'asset', $case->[1]); };
    like($@, qr/supply a valid asset/, "the pattern $case->[0] rejects invalid input");
}
for my $invalid (undef, [], 'invalid', "$value\n", "prefix$value") {
    eval { HostArtifactsInstalledSourceTest::field({ asset => $invalid }, 'asset', qr/hostconfig_[a-z_]+\.tar\.gz/); };
    like($@, qr/supply a valid asset/, 'the boundary rejects values outside the whole-field contract');
}
done_testing();
