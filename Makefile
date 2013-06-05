ifdef B_BASE
USE_BRANDING := yes
IMPORT_BRANDING := yes
include $(B_BASE)/common.mk
include $(B_BASE)/rpmbuild.mk
endif

VENDOR_CODE := xs
VENDOR_NAME := "Citrix Systems, Inc."
LABEL := xs-auto-cert-kit
TEXT := XenServer Auto Cert Kit
VERSION := $(PRODUCT_VERSION)
BUILD := $(BUILD_NUMBER)
KIT_VERSION := $(shell git describe)

STAGING := $(MY_OBJ_DIR)/auto-cert-supp-pack

REPONAME := auto-cert-kit
ifdef B_BASE
REPO := $(call git_loc,$(REPONAME))
else
REPO := .
endif

PYLINT := sh $(REPO)/pylint.sh

SUPP_PACK_ISO := $(MY_OUTPUT_DIR)/xenserver-auto-cert-kit.iso
SUPP_PACK_DIR := $(MY_OUTPUT_DIR)/PACKAGES.auto-cert-kit
SUPP_PACK_ISO_TMP := $(MY_OBJ_DIR)/$(LABEL).iso
SUPP_PACK_ISO_TMP_MD5 := $(SUPP_PACK_ISO_TMP).md5
SUPP_PACK_TARBALL := $(MY_OBJ_DIR)/xenserver-auto-cert-kit.tar.gz
SUPP_PACK_SOURCES := $(MY_OUTPUT_DIR)/SOURCES/xenserver-auto-cert-kit-src.tar.gz
SUPP_PACK_SOURCES_ISO := $(MY_OUTPUT_DIR)/SOURCES/xs-auto-cert-kit-sources.iso

TEST_KIT_RPM := $(MY_OUTPUT_DIR)/RPMS/noarch/xenserver-auto-cert-kit-$(PRODUCT_VERSION)-$(BUILD_NUMBER).noarch.rpm
TEST_KIT_RPM_TMP_DIR := $(MY_OBJ_DIR)/RPM_BUILD_DIRECTORY/tmp/xenserver-auto-cert-kit

TEST_KIT_DEST := /opt/xensource/packages/files/auto-cert-kit
TEST_KIT := $(REPO)/kit
TEST_KIT_SPEC := $(MY_OBJ_DIR)/xenserver-auto-cert-kit.spec

XAPI_PLUGIN_DEST := /etc/xapi.d/plugins
STARTUP_SCRIPT_DEST := /etc/init.d

TMP_SRC_DIR := $(MY_OBJ_DIR)/SOURCES

DEMO_LINUX_XVA := $(PROJECT_OUTPUTDIR)/vpx-dlvm/vpx-dlvm.xva

#ACK_DISTFILES ?= /usr/groups/linux/distfiles/auto-cert-kit/
ACK_DISTFILES = $(MY_DISTFILES)
#Distfile Dependencies
GMP_RPM := $(ACK_DISTFILES)/gmp-4.1.4-10.el5.i386.rpm
GMP_SRC_RPM := $(ACK_DISTFILES)/gmp-4.1.4-10.el5.src.rpm
PY_CRYPTO_RPM := $(ACK_DISTFILES)/python-crypto-2.0.1-13.1.el5.kb.1.i386.rpm
PY_CRYPTO_SRC_RPM := $(ACK_DISTFILES)/python-crypto-2.0.1-13.1.el5.kb.1.src.rpm
PARAMIKO_RPM := $(ACK_DISTFILES)/python-paramiko-1.7.6-1.el5.rf.noarch.rpm
PARAMIKO_SRC_RPM := $(ACK_DISTFILES)/python-paramiko-1.7.6-1.src.rpm
IPERF_RPM := $(ACK_DISTFILES)/iperf-2.0.4-1.el5.rf.i386.rpm
IPERF_SRC_RPM := $(ACK_DISTFILES)/iperf-2.0.4-1.el5.rf.src.rpm
BONNIE_RPM := $(ACK_DISTFILES)/bonnie++-1.94-1.el5.rf.i386.rpm
BONNIE_SRC_RPM := $(ACK_DISTFILES)/bonnie++-1.94-1.rf.src.rpm
IOZONE_RPM := $(ACK_DISTFILES)/iozone-3.394-1.el5.rf.i386.rpm
IOZONE_SRC_RPM := $(ACK_DISTFILES)/iozone-3.394-1.rf.src.rpm
LMBENCH_RPM := $(ACK_DISTFILES)/lmbench-3.0-0.a7.1.el5.rf.i386.rpm
LMBENCH_SRC_RPM := $(ACK_DISTFILES)/lmbench-3.0-0.a7.1.rf.src.rpm
MAKE_RPM := $(ACK_DISTFILES)/make-3.81-3.el5.i386.rpm
MAKE_SRC_RPM := $(ACK_DISTFILES)/make-3.81-3.el5.src.rpm

DEPS := $(GMP_RPM) $(PY_CRYPTO_RPM) $(PARAMIKO_RPM) $(IPERF_RPM) 
SRC_DEPS := $(GMP_SRC_RPM) $(PY_CRYPTO_SRC_RPM) $(PARAMIKO_SRC_RPM) $(IPERF_SRC_RPM) $(BONNIE_SRC_RPM) $(IOZONE_SRC_RPM) $(LMBENCH_SRC_RPM) $(MAKE_SRC_RPM)

OUTPUT := $(SUPP_PACK_ISO)


.PHONY: build
build: $(SUPP_PACK_ISO) $(SUPP_PACK_SOURCES_ISO)
	@:

$(SUPP_PACK_SOURCES): $(SRC_DEPS)
	mkdir -p $(dir $@)
	mkdir -p $(TMP_SRC_DIR)
	cp $(SRC_DEPS) $(TMP_SRC_DIR)/
	tar -C $(MY_OBJ_DIR) -cvf $@ SOURCES/

$(SUPP_PACK_SOURCES_ISO): $(SUPP_PACK_SOURCES)
	mkisofs -A "Citrix" -V "Auto Cert Kit" -J -joliet-long -r -o $@ $(SUPP_PACK_SOURCES)

$(TEST_KIT_SPEC): $(REPO)/xenserver-auto-cert-kit.spec.in
	mkdir -p $(dir $@)
	$(call brand,$^) >$@

$(TEST_KIT_RPM): $(TEST_KIT_SPEC)
	mkdir -p $(dir $@)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(XAPI_PLUGIN_DEST)
	mkdir -p $(TEST_KIT_RPM_TMP_DIR)/$(STARTUP_SCRIPT_DEST)
	cp -r $(REPO)/kit/*.py  $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp -r $(REPO)/kit/*.example $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
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
	cp $(DEMO_LINUX_XVA) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(IPERF_RPM) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(BONNIE_RPM) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(IOZONE_RPM) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(LMBENCH_RPM) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	cp $(MAKE_RPM) $(TEST_KIT_RPM_TMP_DIR)/$(TEST_KIT_DEST)
	$(RPMBUILD) -bb $(TEST_KIT_SPEC)

$(SUPP_PACK_ISO): $(TEST_KIT_RPM) $(DEPS)
	python setup.py --out $(dir $@) --pdn $(PRODUCT_BRAND) --pdv $(PRODUCT_VERSION) --bld $(BUILD) $^

pylint:
	$(PYLINT) $(TEST_KIT)/*.py

clean:
	rm -rf $(MY_OBJ_DIR)/*
	rm -rf $(MY_OUTPUT_DIR)
