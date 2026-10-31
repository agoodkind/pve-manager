include ../defines.mk

all:

export PERLLIB=..

.PHONY: check
check: test-replication test-balloon test-vzdump test-osd test-ceph-health test-ceph-services test-ceph-auth test-ceph-key-migration test-ceph-lockbox-migration test-custom-cpu-models test-pvesh

.PHONY: test-balloon
test-balloon:
	./balloontest.pl

.PHONY: test-replication
test-replication: replication1.t replication2.t replication3.t replication4.t replication5.t replication6.t

replication%.t: replication_test%.pl
	./$<

.PHONY: test-vzdump
test-vzdump: test-vzdump-guest-included test-vzdump-new

.PHONY: test-vzdump-guest-included
test-vzdump-guest-included:
	./vzdump_guest_included_test.pl

.PHONY: test-vzdump-new
test-vzdump-new:
	./vzdump_new_test.pl

.PHONY: test-osd
test-osd:
	./OSD_test.pl

.PHONY: test-ceph-health
test-ceph-health:
	./CephHealth_test.pl

.PHONY: test-ceph-services
test-ceph-services:
	./CephServices_test.pl

.PHONY: test-ceph-auth
test-ceph-auth:
	./CephAuth_test.pl

.PHONY: test-ceph-key-migration
test-ceph-key-migration:
	./CephKeyMigration_test.pl
	./CephKeyMigrationScript_test.pl

.PHONY: test-ceph-lockbox-migration
test-ceph-lockbox-migration:
	./CephLockboxMigration_test.pl

.PHONY: test-custom-cpu-models
test-custom-cpu-models:
	./CustomCPUModels_test.pl

.PHONY: test-pvesh
test-pvesh:
	./pvesh_test.pl

# These targets write below /etc and /var/lib and run as root in a disposable container with
# the overlay access control patch applied. The attestation target also needs the installed
# /usr/bin/gh and HOST_ARTIFACT_FIXTURE_DIR.
.PHONY: test-host-artifacts
test-host-artifacts:
	./HostArtifacts_test.pl

# This target also needs systemd as process 1.
.PHONY: test-host-secrets
test-host-secrets:
	./HostSecrets_test.pl

.PHONY: test-host-artifacts-attestation
test-host-artifacts-attestation:
	./HostArtifacts_attestation_test.pl

.PHONY: install
install:

.PHONY: clean
clean:
	rm -rf *~ .mocked_* *.tmp
