EXTRA_DIST = README FEATURES HISTORY AUTHORS ChangeLog COPYING INSTALL NEWS version cnf platform

SUBDIRS = src include

upload:	dist
	@echo "######## Maintainer only ##########";
	@echo "building files for upload in ftp://ftp-upload.gnu.org/incoming/ftp";
	@echo "building: $(PACKAGE)-$(VERSION).tar.gz.sig";
	gpg -b $(PACKAGE)-$(VERSION).tar.gz
	@echo "version: $(VERSION)" > $(PACKAGE)-$(VERSION).tar.gz.directive
	@echo "directory: $(PACKAGE)" >> $(PACKAGE)-$(VERSION).tar.gz.directive
	@echo "filename: $(PACKAGE)-$(VERSION).tar.gz" >> $(PACKAGE)-$(VERSION).tar.gz.directive
	@echo "building: $(PACKAGE)-$(VERSION).tar.gz.directive.asc";
	gpg --clearsign $(PACKAGE)-$(VERSION).tar.gz.directive
