package PVE::SRIOVLock;

use strict;
use warnings;

use Fcntl qw(:flock);
use PVE::Tools;

use constant PATH => '/run/lock/pve-overlay-sriov.lock';

sub lock_attachment {
    open(my $handle, '>>', PATH) or die "Cannot open the SR-IOV attachment lock: $!\n";
    eval {
        PVE::Tools::run_with_timeout(60, sub {
            flock($handle, LOCK_SH) or die "flock: $!\n";
        });
    };
    die "Cannot acquire the SR-IOV attachment lock: $@" if $@;
    return $handle;
}

1;
