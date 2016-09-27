ifdef B_BASE
USE_BRANDING := yes
IMPORT_BRANDING := yes
include $(B_BASE)/common.mk
include $(B_BASE)/rpmbuild.mk
endif

KIT_VERSION := $(shell git describe)

REPONAME := auto-cert-kit
ifdef B_BASE
REPO := $(call git_loc,$(REPONAME))
else
REPO := .
endif

PYLINT := sh $(REPO)/pylint.sh

PY_PACKAGE := pypackages
TEST_KIT_RPM := $(MY_OUTPUT_DIR)/RPMS/noarch/xenserver-auto-cert-kit-$(PRODUCT_VERSION)-$(BUILD_NUMBER).noarch.rpm
TEST_KIT_RPM_TMP_DIR := $(MY_OBJ_DIR)/RPM_BUILD_DIRECTORY/tmp/xenserver-auto-cert-kit

TEST_KIT_DEST := /opt/xensource/packages/files/auto-cert-kit
TEST_KIT := $(REPO)/autocertkit
TEST_KIT_SPEC := $(MY_OBJ_DIR)/xenserver-auto-cert-kit.spec

XAPI_PLUGIN_DEST := /etc/xapi.d/plugins
STARTUP_SCRIPT_DEST := /etc/init.d

TMP_SRC_DIR := $(MY_OBJ_DIR)/SOURCES

#ACK_DISTFILES ?= /usr/groups/linux/distfiles/auto-cert-kit/
ACK_DISTFILES = $(MY_DISTFILES)

#DEMO_LINUX_XVA := $(PROJECT_OUTPUTDIR)/vpx-dlvm/vpx-dlvm.xva
DEMO_LINUX_XVA := $(ACK_DISTFILES)/vpx-dlvm.xva

# packages installed on domain0
DOM0_RPMS :=
# packages to be installed on VM
VM_RPMS   :=
# source packages
SRC_RPMS  :=

ifeq ($(shell rpm -q centos-release --qf '%{version}\n'),5)
DOM0_RPMS += $(ACK_DISTFILES)/gmp-4.1.4-10.el5.$(DOMAIN0_ARCH).rpm
SRC_RPMS  += $(ACK_DISTFILES)/gmp-4.1.4-10.el5.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/python-crypto-2.0.1-13.1.el5.kb.1.$(DOMAIN0_ARCH).rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-crypto-2.0.1-13.1.el5.kb.1.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/python-paramiko-1.7.6-1.el5.rf.noarch.rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-paramiko-1.7.6-1.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/iperf-2.0.4-1.el5.rf.$(DOMAIN0_ARCH).rpm
else ifeq ($(shell rpm -q centos-release --qf '%{version}\n'),6)
DOM0_RPMS += $(ACK_DISTFILES)/python-crypto-2.0.1-22.el6.$(DOMAIN0_ARCH).rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-crypto-2.0.1-22.el6.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/python-paramiko-1.7.5-2.1.el6.noarch.rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-paramiko-1.7.5-2.1.el6.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/iperf-2.0.5-3.el6.$(DOMAIN0_ARCH).rpm
SRC_RPMS  += $(ACK_DISTFILES)/iperf-2.0.5-3.el6.src.rpm
else
DOM0_RPMS += $(ACK_DISTFILES)/python-six-1.3.0-4.el7.noarch.rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-six-1.3.0-4.el7.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/python-ecdsa-0.11-3.el7.noarch.rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-ecdsa-0.11-3.el7.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/python-crypto-2.6.1-1.el7.$(DOMAIN0_ARCH).rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-crypto-2.6.1-1.el7.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/python-paramiko-1.12.4-1.el7.noarch.rpm
SRC_RPMS  += $(ACK_DISTFILES)/python-paramiko-1.12.4-1.el7.src.rpm
DOM0_RPMS += $(ACK_DISTFILES)/iperf-2.0.4-1.el7.rf.$(DOMAIN0_ARCH).rpm
SRC_RPMS  += $(ACK_DISTFILES)/iperf-2.0.4-1.rf.src.rpm
endif

VM_RPMS   += $(ACK_DISTFILES)/iperf-2.0.4-1.el5.rf.i386.rpm
SRC_RPMS  += $(ACK_DISTFILES)/iperf-2.0.4-1.el5.rf.src.rpm
VM_RPMS   += $(ACK_DISTFILES)/bonnie++-1.94-1.el5.rf.i386.rpm
SRC_RPMS  += $(ACK_DISTFILES)/bonnie++-1.94-1.rf.src.rpm
VM_RPMS   += $(ACK_DISTFILES)/iozone-3.394-1.el5.rf.i386.rpm
SRC_RPMS  += $(ACK_DISTFILES)/iozone-3.394-1.rf.src.rpm
VM_RPMS   += $(ACK_DISTFILES)/lmbench-3.0-0.a7.1.el5.rf.i386.rpm
SRC_RPMS  += $(ACK_DISTFILES)/lmbench-3.0-0.a7.1.rf.src.rpm
VM_RPMS   += $(ACK_DISTFILES)/make-3.81-3.el5.i386.rpm
SRC_RPMS  += $(ACK_DISTFILES)/make-3.81-3.el5.src.rpm

# Definition of the pack.
PACK_LABEL := xenserver-auto-cert-kit
PACK_VERSION := $(PRODUCT_VERSION)
PACK_UUID := 9815300b-9faf-4b8f-82a3-a7cfb02a46c4
PACK_DESCRIPTION := XenServer Auto Cert Kit

# Contents of the pack.
PACK_PACKAGES = $(TEST_KIT_RPM) $(DOM0_RPMS)

# Generated outputs
ISO := $(MY_OUTPUT_DIR)/$(PACK_LABEL).iso
SRCS := $(MY_OUTPUT_DIR)/$(PACK_LABEL)-sources.tar

BUILD_DIR := $(MY_OBJ_DIR)/$(PACK_LABEL)

BASE_REQUIRES ?= platform-version = $(PLATFORM_VERSION)

GPG_KEY_FILE := RPM-GPG-KEY-XS-Eng-Test
GPG_OPTIONS := --homedir=/.gpg --lock-never --batch --yes
GPG_UID := $(shell gpg $(GPG_OPTIONS) -k --with-colons 2>/dev/null | awk -F: '$$1=="uid" {print $$10}')

.PHONY: build
build: $(ISO) $(SRCS)
	@:

$(TEST_KIT_SPEC): $(REPO)/xenserver-auto-cert-kit.spec.in
	mkdir -p $(dir $@)
	$(call brand,$^) >$@

$(TEST_KIT_RPM): $(TEST_KIT_SPEC) $(RPM_DIRECTORIES)
	rm -rf $(dir $@)
	mkdir -p $(dir $@)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/$(PY_PACKAGE)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/$(PY_PACKAGE)/acktools
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/$(PY_PACKAGE)/acktools/net
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(XAPI_PLUGIN_DEST)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(STARTUP_SCRIPT_DEST)
	cp -r $(TEST_KIT)/*.py  $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp -r $(TEST_KIT)/*.example $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	sed -i 's/@PRODUCT_VERSION@/$(PRODUCT_VERSION)/g' \
		$(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/*.py
	sed -i 's/@BUILD_NUMBER@/$(BUILD_NUMBER)/g' \
		$(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/*.py
	sed -i 's/@KIT_VERSION@/$(KIT_VERSION)/g' \
		$(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/*.py
	cp -r $(REPO)/overlay/* $(TEST_KIT_RPM_TMP_DIR)/
	cp -r $(REPO)/plugins/* $(TEST_KIT_RPM_TMP_DIR)/$(XAPI_PLUGIN_DEST)
	cp -r $(REPO)/init.d/* $(TEST_KIT_RPM_TMP_DIR)/$(STARTUP_SCRIPT_DEST)
	cp -r $(REPO)/config $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(REPO)/acktools/*.py $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/$(PY_PACKAGE)/acktools/
	cp $(REPO)/acktools/net/*.py $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/$(PY_PACKAGE)/acktools/net/
	cp -r $(REPO)/mk/acktools-setup.py $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)/$(PY_PACKAGE)/setup.py
	cp $(DEMO_LINUX_XVA) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(VM_RPMS) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cd $(TEST_KIT_RPM_TMP_DIR) && tar zcvf $(RPM_SOURCESDIR)/auto-cert-kit.tar.gz *
	$(RPMBUILD) -bb $(TEST_KIT_SPEC)

$(ISO): $(MY_OUTPUT_DIR)/.dirstamp $(PACK_PACKAGES)
	GNUPGHOME=/.gpg build-update --uuid $(PACK_UUID) --label "$(PACK_LABEL)" --version $(PACK_VERSION) \
		--description "$(PACK_DESCRIPTION)" --base-requires "$(BASE_REQUIRES)" $(PACK_GUIDANCE:%=--after-apply %) \
		$(PACK_PRECHECK:%=--precheck %) $(PACK_REMOVE:%=--remove %) \
		--key "$(GPG_UID)" --keyfile $(GPG_KEY_FILE) --no-passphrase \
		-o $@ $(PACK_PACKAGES)

$(SRCS): $(SRC_RPMS)
	mkdir -p $(dir $@)
	mkdir -p $(TMP_SRC_DIR)
	cp $(SRC_RPMS) $(TMP_SRC_DIR)/
	tar -C $(MY_OBJ_DIR)/SOURCES -cvf $@ .

pylint:
	$(PYLINT) $(TEST_KIT)/*.py

clean:
	rm -rf $(MY_OBJ_DIR)/*
	rm -rf $(MY_OUTPUT_DIR)
