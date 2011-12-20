srcdir = /root/php-5.3.8
builddir = /root/php-5.3.8
top_srcdir = /root/php-5.3.8
top_builddir = /root/php-5.3.8
EGREP = grep -E
SED = /bin/sed
CONFIGURE_COMMAND = './configure' '--with-uwsgi=/root/uwsgi' '--prefix=/opt/php' '--with-mysql' '--disable-cli'
CONFIGURE_OPTIONS = '--with-uwsgi=/root/uwsgi' '--prefix=/opt/php' '--with-mysql' '--disable-cli'
PHP_MAJOR_VERSION = 5
PHP_MINOR_VERSION = 3
PHP_RELEASE_VERSION = 8
PHP_EXTRA_VERSION =
AWK = gawk
YACC = exit 0;
RE2C = exit 0;
RE2C_FLAGS =
SHLIB_SUFFIX_NAME = so
SHLIB_DL_SUFFIX_NAME = so
PROG_SENDMAIL = /usr/sbin/sendmail
SQLITE3_SHARED_LIBADD =
DOM_SHARED_LIBADD =
FILTER_SHARED_LIBADD =
ICONV_SHARED_LIBADD =
JSON_SHARED_LIBADD =
MYSQL_MODULE_TYPE = external
MYSQL_LIBS = -L/usr/lib -lmysqlclient
MYSQL_INCLUDE = -I/usr/include/mysql
MYSQL_SHARED_LIBADD =
PDO_SQLITE_SHARED_LIBADD =
SESSION_SHARED_LIBADD =
SIMPLEXML_SHARED_LIBADD =
LEMON = exit 0;
SQLITE_SHARED_LIBADD =
SQLITE_ENCODING = ISO8859
SQLITE_VERSION = 2.8.17
XML_SHARED_LIBADD =
XMLREADER_SHARED_LIBADD =
XMLWRITER_SHARED_LIBADD =
PHP_INSTALLED_SAPIS = uwsgi
PHP_EXECUTABLE =
PHP_CLI_TARGET =
PHP_SAPI_OBJS = sapi/uwsgi/php_plugin.lo main/internal_functions.lo
PHP_CLI_OBJS = main/internal_functions_cli.lo
PHP_GLOBAL_OBJS = ext/date/php_date.lo ext/date/lib/astro.lo ext/date/lib/dow.lo ext/date/lib/parse_date.lo ext/date/lib/parse_tz.lo ext/date/lib/timelib.lo ext/date/lib/tm2unixtime.lo ext/date/lib/unixtime2tm.lo ext/date/lib/parse_iso_intervals.lo ext/date/lib/interval.lo ext/ereg/ereg.lo ext/ereg/regex/regcomp.lo ext/ereg/regex/regexec.lo ext/ereg/regex/regerror.lo ext/ereg/regex/regfree.lo ext/libxml/libxml.lo ext/pcre/pcrelib/pcre_chartables.lo ext/pcre/pcrelib/pcre_ucd.lo ext/pcre/pcrelib/pcre_compile.lo ext/pcre/pcrelib/pcre_config.lo ext/pcre/pcrelib/pcre_exec.lo ext/pcre/pcrelib/pcre_fullinfo.lo ext/pcre/pcrelib/pcre_get.lo ext/pcre/pcrelib/pcre_globals.lo ext/pcre/pcrelib/pcre_info.lo ext/pcre/pcrelib/pcre_maketables.lo ext/pcre/pcrelib/pcre_newline.lo ext/pcre/pcrelib/pcre_ord2utf8.lo ext/pcre/pcrelib/pcre_refcount.lo ext/pcre/pcrelib/pcre_study.lo ext/pcre/pcrelib/pcre_tables.lo ext/pcre/pcrelib/pcre_try_flipped.lo ext/pcre/pcrelib/pcre_valid_utf8.lo ext/pcre/pcrelib/pcre_version.lo ext/pcre/pcrelib/pcre_xclass.lo ext/pcre/php_pcre.lo ext/sqlite3/sqlite3.lo ext/sqlite3/libsqlite/sqlite3.lo ext/ctype/ctype.lo ext/dom/php_dom.lo ext/dom/attr.lo ext/dom/document.lo ext/dom/domerrorhandler.lo ext/dom/domstringlist.lo ext/dom/domexception.lo ext/dom/namelist.lo ext/dom/processinginstruction.lo ext/dom/cdatasection.lo ext/dom/documentfragment.lo ext/dom/domimplementation.lo ext/dom/element.lo ext/dom/node.lo ext/dom/string_extend.lo ext/dom/characterdata.lo ext/dom/documenttype.lo ext/dom/domimplementationlist.lo ext/dom/entity.lo ext/dom/nodelist.lo ext/dom/text.lo ext/dom/comment.lo ext/dom/domconfiguration.lo ext/dom/domimplementationsource.lo ext/dom/entityreference.lo ext/dom/notation.lo ext/dom/xpath.lo ext/dom/dom_iterators.lo ext/dom/typeinfo.lo ext/dom/domerror.lo ext/dom/domlocator.lo ext/dom/namednodemap.lo ext/dom/userdatahandler.lo ext/fileinfo/fileinfo.lo ext/fileinfo/libmagic/apprentice.lo ext/fileinfo/libmagic/apptype.lo ext/fileinfo/libmagic/ascmagic.lo ext/fileinfo/libmagic/cdf.lo ext/fileinfo/libmagic/cdf_time.lo ext/fileinfo/libmagic/compress.lo ext/fileinfo/libmagic/encoding.lo ext/fileinfo/libmagic/fsmagic.lo ext/fileinfo/libmagic/funcs.lo ext/fileinfo/libmagic/is_tar.lo ext/fileinfo/libmagic/magic.lo ext/fileinfo/libmagic/print.lo ext/fileinfo/libmagic/readcdf.lo ext/fileinfo/libmagic/readelf.lo ext/fileinfo/libmagic/softmagic.lo ext/filter/filter.lo ext/filter/sanitizing_filters.lo ext/filter/logical_filters.lo ext/filter/callback_filter.lo ext/hash/hash.lo ext/hash/hash_md.lo ext/hash/hash_sha.lo ext/hash/hash_ripemd.lo ext/hash/hash_haval.lo ext/hash/hash_tiger.lo ext/hash/hash_gost.lo ext/hash/hash_snefru.lo ext/hash/hash_whirlpool.lo ext/hash/hash_adler32.lo ext/hash/hash_crc32.lo ext/hash/hash_salsa.lo ext/iconv/iconv.lo ext/json/json.lo ext/json/utf8_to_utf16.lo ext/json/utf8_decode.lo ext/json/JSON_parser.lo ext/mysql/php_mysql.lo ext/pdo/pdo.lo ext/pdo/pdo_dbh.lo ext/pdo/pdo_stmt.lo ext/pdo/pdo_sql_parser.lo ext/pdo/pdo_sqlstate.lo ext/pdo_sqlite/pdo_sqlite.lo ext/pdo_sqlite/sqlite_driver.lo ext/pdo_sqlite/sqlite_statement.lo ext/phar/util.lo ext/phar/tar.lo ext/phar/zip.lo ext/phar/stream.lo ext/phar/func_interceptors.lo ext/phar/dirstream.lo ext/phar/phar.lo ext/phar/phar_object.lo ext/phar/phar_path_check.lo ext/posix/posix.lo ext/reflection/php_reflection.lo ext/session/session.lo ext/session/mod_files.lo ext/session/mod_mm.lo ext/session/mod_user.lo ext/simplexml/simplexml.lo ext/simplexml/sxe.lo ext/spl/php_spl.lo ext/spl/spl_functions.lo ext/spl/spl_engine.lo ext/spl/spl_iterators.lo ext/spl/spl_array.lo ext/spl/spl_directory.lo ext/spl/spl_exceptions.lo ext/spl/spl_observer.lo ext/spl/spl_dllist.lo ext/spl/spl_heap.lo ext/spl/spl_fixedarray.lo ext/sqlite/sqlite.lo ext/sqlite/sess_sqlite.lo ext/sqlite/pdo_sqlite2.lo ext/sqlite/libsqlite/src/opcodes.lo ext/sqlite/libsqlite/src/parse.lo ext/sqlite/libsqlite/src/encode.lo ext/sqlite/libsqlite/src/auth.lo ext/sqlite/libsqlite/src/btree.lo ext/sqlite/libsqlite/src/build.lo ext/sqlite/libsqlite/src/delete.lo ext/sqlite/libsqlite/src/expr.lo ext/sqlite/libsqlite/src/func.lo ext/sqlite/libsqlite/src/hash.lo ext/sqlite/libsqlite/src/insert.lo ext/sqlite/libsqlite/src/main.lo ext/sqlite/libsqlite/src/os.lo ext/sqlite/libsqlite/src/pager.lo ext/sqlite/libsqlite/src/printf.lo ext/sqlite/libsqlite/src/random.lo ext/sqlite/libsqlite/src/select.lo ext/sqlite/libsqlite/src/table.lo ext/sqlite/libsqlite/src/tokenize.lo ext/sqlite/libsqlite/src/update.lo ext/sqlite/libsqlite/src/util.lo ext/sqlite/libsqlite/src/vdbe.lo ext/sqlite/libsqlite/src/attach.lo ext/sqlite/libsqlite/src/btree_rb.lo ext/sqlite/libsqlite/src/pragma.lo ext/sqlite/libsqlite/src/vacuum.lo ext/sqlite/libsqlite/src/copy.lo ext/sqlite/libsqlite/src/vdbeaux.lo ext/sqlite/libsqlite/src/date.lo ext/sqlite/libsqlite/src/where.lo ext/sqlite/libsqlite/src/trigger.lo ext/standard/crypt_freesec.lo ext/standard/crypt_blowfish.lo ext/standard/crypt_sha512.lo ext/standard/crypt_sha256.lo ext/standard/php_crypt_r.lo ext/standard/array.lo ext/standard/base64.lo ext/standard/basic_functions.lo ext/standard/browscap.lo ext/standard/crc32.lo ext/standard/crypt.lo ext/standard/cyr_convert.lo ext/standard/datetime.lo ext/standard/dir.lo ext/standard/dl.lo ext/standard/dns.lo ext/standard/exec.lo ext/standard/file.lo ext/standard/filestat.lo ext/standard/flock_compat.lo ext/standard/formatted_print.lo ext/standard/fsock.lo ext/standard/head.lo ext/standard/html.lo ext/standard/image.lo ext/standard/info.lo ext/standard/iptc.lo ext/standard/lcg.lo ext/standard/link.lo ext/standard/mail.lo ext/standard/math.lo ext/standard/md5.lo ext/standard/metaphone.lo ext/standard/microtime.lo ext/standard/pack.lo ext/standard/pageinfo.lo ext/standard/quot_print.lo ext/standard/rand.lo ext/standard/soundex.lo ext/standard/string.lo ext/standard/scanf.lo ext/standard/syslog.lo ext/standard/type.lo ext/standard/uniqid.lo ext/standard/url.lo ext/standard/var.lo ext/standard/versioning.lo ext/standard/assert.lo ext/standard/strnatcmp.lo ext/standard/levenshtein.lo ext/standard/incomplete_class.lo ext/standard/url_scanner_ex.lo ext/standard/ftp_fopen_wrapper.lo ext/standard/http_fopen_wrapper.lo ext/standard/php_fopen_wrapper.lo ext/standard/credits.lo ext/standard/css.lo ext/standard/var_unserializer.lo ext/standard/ftok.lo ext/standard/sha1.lo ext/standard/user_filters.lo ext/standard/uuencode.lo ext/standard/filters.lo ext/standard/proc_open.lo ext/standard/streamsfuncs.lo ext/standard/http.lo ext/tokenizer/tokenizer.lo ext/tokenizer/tokenizer_data.lo ext/xml/xml.lo ext/xml/compat.lo ext/xmlreader/php_xmlreader.lo ext/xmlwriter/php_xmlwriter.lo TSRM/TSRM.lo TSRM/tsrm_strtok_r.lo TSRM/tsrm_virtual_cwd.lo main/main.lo main/snprintf.lo main/spprintf.lo main/php_sprintf.lo main/safe_mode.lo main/fopen_wrappers.lo main/alloca.lo main/php_scandir.lo main/php_ini.lo main/SAPI.lo main/rfc1867.lo main/php_content_types.lo main/strlcpy.lo main/strlcat.lo main/mergesort.lo main/reentrancy.lo main/php_variables.lo main/php_ticks.lo main/network.lo main/php_open_temporary_file.lo main/php_logos.lo main/output.lo main/getopt.lo main/streams/streams.lo main/streams/cast.lo main/streams/memory.lo main/streams/filter.lo main/streams/plain_wrapper.lo main/streams/userspace.lo main/streams/transports.lo main/streams/xp_socket.lo main/streams/mmap.lo main/streams/glob_wrapper.lo Zend/zend_language_parser.lo Zend/zend_language_scanner.lo Zend/zend_ini_parser.lo Zend/zend_ini_scanner.lo Zend/zend_alloc.lo Zend/zend_compile.lo Zend/zend_constants.lo Zend/zend_dynamic_array.lo Zend/zend_execute_API.lo Zend/zend_highlight.lo Zend/zend_llist.lo Zend/zend_opcode.lo Zend/zend_operators.lo Zend/zend_ptr_stack.lo Zend/zend_stack.lo Zend/zend_variables.lo Zend/zend.lo Zend/zend_API.lo Zend/zend_extensions.lo Zend/zend_hash.lo Zend/zend_list.lo Zend/zend_indent.lo Zend/zend_builtin_functions.lo Zend/zend_sprintf.lo Zend/zend_ini.lo Zend/zend_qsort.lo Zend/zend_multibyte.lo Zend/zend_ts_hash.lo Zend/zend_stream.lo Zend/zend_iterators.lo Zend/zend_interfaces.lo Zend/zend_exceptions.lo Zend/zend_strtod.lo Zend/zend_gc.lo Zend/zend_closures.lo Zend/zend_float.lo Zend/zend_objects.lo Zend/zend_object_handlers.lo Zend/zend_objects_API.lo Zend/zend_default_classes.lo Zend/zend_execute.lo
PHP_MODULES =
PHP_ZEND_EX =
EXT_LIBS =
abs_builddir = /root/php-5.3.8
abs_srcdir = /root/php-5.3.8
php_abs_top_builddir = /root/php-5.3.8
php_abs_top_srcdir = /root/php-5.3.8
bindir = ${exec_prefix}/bin
sbindir = ${exec_prefix}/sbin
exec_prefix = ${prefix}
program_prefix =
program_suffix =
includedir = ${prefix}/include
libdir = ${exec_prefix}/lib/php
mandir = ${prefix}/man
phplibdir = /root/uwsgi/modules
phptempdir = /root/uwsgi/libs
prefix = /opt/php
localstatedir = ${prefix}/var
datadir = ${prefix}/share/php
datarootdir = /opt/php/php
sysconfdir = ${prefix}/etc
EXEEXT =
CC = gcc
CFLAGS = $(CFLAGS_CLEAN)
CFLAGS_CLEAN = -I/usr/include -g -O2 -fvisibility=hidden
CPP = gcc -E
CPPFLAGS =
CXX =
CXXFLAGS =
CXXFLAGS_CLEAN =
DEBUG_CFLAGS =
EXTENSION_DIR = /opt/php/lib/php/extensions/no-debug-non-zts-
EXTRA_LDFLAGS = -avoid-version -module
EXTRA_LDFLAGS_PROGRAM =
EXTRA_LIBS = -lcrypt -lresolv -lcrypt -lrt -lmysqlclient -lrt -lm -ldl -lnsl -lxml2 -lxml2 -lxml2 -lcrypt -lxml2 -lxml2 -lxml2 -lcrypt
ZEND_EXTRA_LIBS =
INCLUDES = -I/lib -I/root/php-5.3.8/ext/date/lib -I/root/php-5.3.8/ext/ereg/regex -I/usr/include/libxml2 -I/usr/include/mysql -I/root/php-5.3.8/ext/sqlite3/libsqlite -I$(top_builddir)/TSRM -I$(top_builddir)/Zend
EXTRA_INCLUDES =
INCLUDE_PATH = .:
INSTALL_IT = $(INSTALL) -m 0755 libs/libphp5.so $(PHP_UWSGI)/php_plugin.so
LFLAGS =
LIBTOOL = $(SHELL) $(top_builddir)/libtool --silent --preserve-dup-deps
LN_S = ln -s
NATIVE_RPATHS =
PEAR_INSTALLDIR =
PHP_BUILD_DATE = 2011-12-20
PHP_LDFLAGS =
PHP_LIBS =
OVERALL_TARGET = libphp5.la
PHP_RPATHS =
PHP_SAPI = uwsgi
PHP_VERSION = 5.3.8
PHP_VERSION_ID = 50308
SHELL = /bin/sh
SHARED_LIBTOOL = $(LIBTOOL)
WARNING_LEVEL =
PHP_FRAMEWORKS =
PHP_FRAMEWORKPATH =
INSTALL_HEADERS = ext/date/php_date.h ext/date/lib/timelib.h ext/date/lib/timelib_structs.h ext/date/lib/timelib_config.h ext/ereg/php_ereg.h ext/ereg/php_regex.h ext/ereg/regex/ ext/libxml/php_libxml.h ext/pcre/php_pcre.h ext/pcre/pcrelib/ ext/sqlite3/libsqlite/sqlite3.h ext/dom/xml_common.h ext/filter/php_filter.h ext/hash/php_hash.h ext/hash/php_hash_md.h ext/hash/php_hash_sha.h ext/hash/php_hash_ripemd.h ext/hash/php_hash_haval.h ext/hash/php_hash_tiger.h ext/hash/php_hash_gost.h ext/hash/php_hash_snefru.h ext/hash/php_hash_whirlpool.h ext/hash/php_hash_adler32.h ext/hash/php_hash_crc32.h ext/hash/php_hash_salsa.h ext/hash/php_hash_types.h ext/iconv/ ext/json/php_json.h ext/pdo/php_pdo.h ext/pdo/php_pdo_driver.h ext/session/php_session.h ext/session/mod_files.h ext/session/mod_user.h ext/spl/php_spl.h ext/spl/spl_array.h ext/spl/spl_directory.h ext/spl/spl_engine.h ext/spl/spl_exceptions.h ext/spl/spl_functions.h ext/spl/spl_iterators.h ext/spl/spl_observer.h ext/spl/spl_dllist.h ext/spl/spl_heap.h ext/spl/spl_fixedarray.h ext/sqlite/libsqlite/src/sqlite.h ext/standard/ ext/xml/ Zend/ TSRM/ include/ main/ main/streams/
ZEND_EXT_TYPE = zend_extension
all_targets = $(OVERALL_TARGET) $(PHP_MODULES) $(PHP_ZEND_EX) $(PHP_CLI_TARGET)
install_targets = install-sapi install-build install-headers install-programs
mkinstalldirs = $(top_srcdir)/build/shtool mkdir -p
INSTALL = $(top_srcdir)/build/shtool install -c
INSTALL_DATA = $(INSTALL) -m 644

DEFS = -DPHP_ATOM_INC -I$(top_builddir)/include -I$(top_builddir)/main -I$(top_srcdir)
COMMON_FLAGS = $(DEFS) $(INCLUDES) $(EXTRA_INCLUDES) $(CPPFLAGS) $(PHP_FRAMEWORKPATH)

all: $(all_targets) 
	@echo
	@echo "Build complete."
	@echo "Don't forget to run 'make test'."
	@echo
	
build-modules: $(PHP_MODULES) $(PHP_ZEND_EX)

libphp$(PHP_MAJOR_VERSION).la: $(PHP_GLOBAL_OBJS) $(PHP_SAPI_OBJS)
	$(LIBTOOL) --mode=link $(CC) $(CFLAGS) $(EXTRA_CFLAGS) -rpath $(phptempdir) $(EXTRA_LDFLAGS) $(LDFLAGS) $(PHP_RPATHS) $(PHP_GLOBAL_OBJS) $(PHP_SAPI_OBJS) $(EXTRA_LIBS) $(ZEND_EXTRA_LIBS) -o $@
	-@$(LIBTOOL) --silent --mode=install cp $@ $(phptempdir)/$@ >/dev/null 2>&1

libs/libphp$(PHP_MAJOR_VERSION).bundle: $(PHP_GLOBAL_OBJS) $(PHP_SAPI_OBJS)
	$(CC) $(MH_BUNDLE_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS) $(LDFLAGS) $(EXTRA_LDFLAGS) $(PHP_GLOBAL_OBJS:.lo=.o) $(PHP_SAPI_OBJS:.lo=.o) $(PHP_FRAMEWORKS) $(EXTRA_LIBS) $(ZEND_EXTRA_LIBS) -o $@ && cp $@ libs/libphp$(PHP_MAJOR_VERSION).so

install: $(all_targets) $(install_targets)

install-sapi: $(OVERALL_TARGET)
	@echo "Installing PHP SAPI module:       $(PHP_SAPI)"
	-@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	-@if test ! -r $(phptempdir)/libphp$(PHP_MAJOR_VERSION).$(SHLIB_DL_SUFFIX_NAME); then \
		for i in 0.0.0 0.0 0; do \
			if test -r $(phptempdir)/libphp$(PHP_MAJOR_VERSION).$(SHLIB_DL_SUFFIX_NAME).$$i; then \
				$(LN_S) $(phptempdir)/libphp$(PHP_MAJOR_VERSION).$(SHLIB_DL_SUFFIX_NAME).$$i $(phptempdir)/libphp$(PHP_MAJOR_VERSION).$(SHLIB_DL_SUFFIX_NAME); \
				break; \
			fi; \
		done; \
	fi
	@$(INSTALL_IT)

install-modules: build-modules
	@test -d modules && \
	$(mkinstalldirs) $(INSTALL_ROOT)$(EXTENSION_DIR)
	@echo "Installing shared extensions:     $(INSTALL_ROOT)$(EXTENSION_DIR)/"
	@rm -f modules/*.la >/dev/null 2>&1
	@$(INSTALL) modules/* $(INSTALL_ROOT)$(EXTENSION_DIR)

install-headers:
	-@if test "$(INSTALL_HEADERS)"; then \
		for i in `echo $(INSTALL_HEADERS)`; do \
			i=`$(top_srcdir)/build/shtool path -d $$i`; \
			paths="$$paths $(INSTALL_ROOT)$(phpincludedir)/$$i"; \
		done; \
		$(mkinstalldirs) $$paths && \
		echo "Installing header files:          $(INSTALL_ROOT)$(phpincludedir)/" && \
		for i in `echo $(INSTALL_HEADERS)`; do \
			if test "$(PHP_PECL_EXTENSION)"; then \
				src=`echo $$i | $(SED) -e "s#ext/$(PHP_PECL_EXTENSION)/##g"`; \
			else \
				src=$$i; \
			fi; \
			if test -f "$(top_srcdir)/$$src"; then \
				$(INSTALL_DATA) $(top_srcdir)/$$src $(INSTALL_ROOT)$(phpincludedir)/$$i; \
			elif test -f "$(top_builddir)/$$src"; then \
				$(INSTALL_DATA) $(top_builddir)/$$src $(INSTALL_ROOT)$(phpincludedir)/$$i; \
			else \
				(cd $(top_srcdir)/$$src && $(INSTALL_DATA) *.h $(INSTALL_ROOT)$(phpincludedir)/$$i; \
				cd $(top_builddir)/$$src && $(INSTALL_DATA) *.h $(INSTALL_ROOT)$(phpincludedir)/$$i) 2>/dev/null || true; \
			fi \
		done; \
	fi

PHP_TEST_SETTINGS = -d 'open_basedir=' -d 'output_buffering=0' -d 'memory_limit=-1'
PHP_TEST_SHARED_EXTENSIONS =  ` \
	if test "x$(PHP_MODULES)" != "x"; then \
		for i in $(PHP_MODULES)""; do \
			. $$i; $(top_srcdir)/build/shtool echo -n -- " -d extension=$$dlname"; \
		done; \
	fi; \
	if test "x$(PHP_ZEND_EX)" != "x"; then \
		for i in $(PHP_ZEND_EX)""; do \
			. $$i; $(top_srcdir)/build/shtool echo -n -- " -d $(ZEND_EXT_TYPE)=$(top_builddir)/modules/$$dlname"; \
		done; \
	fi`
PHP_DEPRECATED_DIRECTIVES_REGEX = '^(define_syslog_variables|register_(globals|long_arrays)?|safe_mode|magic_quotes_(gpc|runtime|sybase)?|(zend_)?extension(_debug)?(_ts)?)[\t\ ]*='

test: all
	-@if test ! -z "$(PHP_EXECUTABLE)" && test -x "$(PHP_EXECUTABLE)"; then \
		INI_FILE=`$(PHP_EXECUTABLE) -d 'display_errors=stderr' -r 'echo php_ini_loaded_file();' 2> /dev/null`; \
		if test "$$INI_FILE"; then \
			$(EGREP) -h -v $(PHP_DEPRECATED_DIRECTIVES_REGEX) "$$INI_FILE" > $(top_builddir)/tmp-php.ini; \
		else \
			echo > $(top_builddir)/tmp-php.ini; \
		fi; \
		INI_SCANNED_PATH=`$(PHP_EXECUTABLE) -d 'display_errors=stderr' -r '$$a = explode(",\n", trim(php_ini_scanned_files())); echo $$a[0];' 2> /dev/null`; \
		if test "$$INI_SCANNED_PATH"; then \
			INI_SCANNED_PATH=`$(top_srcdir)/build/shtool path -d $$INI_SCANNED_PATH`; \
			$(EGREP) -h -v $(PHP_DEPRECATED_DIRECTIVES_REGEX) "$$INI_SCANNED_PATH"/*.ini >> $(top_builddir)/tmp-php.ini; \
		fi; \
		TEST_PHP_EXECUTABLE=$(PHP_EXECUTABLE) \
		TEST_PHP_SRCDIR=$(top_srcdir) \
		CC="$(CC)" \
			$(PHP_EXECUTABLE) -n -c $(top_builddir)/tmp-php.ini $(PHP_TEST_SETTINGS) $(top_srcdir)/run-tests.php -n -c $(top_builddir)/tmp-php.ini -d extension_dir=$(top_builddir)/modules/ $(PHP_TEST_SHARED_EXTENSIONS) $(TESTS); \
		rm $(top_builddir)/tmp-php.ini; \
	else \
		echo "ERROR: Cannot run tests without CLI sapi."; \
	fi

clean:
	find . -name \*.gcno -o -name \*.gcda | xargs rm -f
	find . -name \*.lo -o -name \*.o | xargs rm -f
	find . -name \*.la -o -name \*.a | xargs rm -f 
	find . -name \*.so | xargs rm -f
	find . -name .libs -a -type d|xargs rm -rf
	rm -f libphp$(PHP_MAJOR_VERSION).la $(SAPI_CLI_PATH) $(OVERALL_TARGET) modules/* libs/*

distclean: clean
	rm -f Makefile config.cache config.log config.status Makefile.objects Makefile.fragments libtool main/php_config.h stamp-h sapi/apache/libphp$(PHP_MAJOR_VERSION).module buildmk.stamp
	$(EGREP) define'.*include/php' $(top_srcdir)/configure | $(SED) 's/.*>//'|xargs rm -f

.PHONY: all clean install distclean test
.NOEXPORT:

ext/fileinfo/libmagic/apprentice.lo: /root/php-5.3.8/ext/fileinfo/data_file.c
phpincludedir=$(prefix)/include/php

PDO_HEADER_FILES= \
	php_pdo.h \
	php_pdo_driver.h

install-pdo-headers:
	@echo "Installing PDO headers:          $(INSTALL_ROOT)$(phpincludedir)/ext/pdo/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(phpincludedir)/ext/pdo
	@for f in $(PDO_HEADER_FILES); do \
		if test -f "$(top_srcdir)/$$f"; then \
			$(INSTALL_DATA) $(top_srcdir)/$$f $(INSTALL_ROOT)$(phpincludedir)/ext/pdo; \
		elif test -f "$(top_builddir)/$$f"; then \
			$(INSTALL_DATA) $(top_builddir)/$$f $(INSTALL_ROOT)$(phpincludedir)/ext/pdo; \
		elif test -f "$(top_srcdir)/ext/pdo/$$f"; then \
			$(INSTALL_DATA) $(top_srcdir)/ext/pdo/$$f $(INSTALL_ROOT)$(phpincludedir)/ext/pdo; \
		elif test -f "$(top_builddir)/ext/pdo/$$f"; then \
			$(INSTALL_DATA) $(top_builddir)/ext/pdo/$$f $(INSTALL_ROOT)$(phpincludedir)/ext/pdo; \
		else \
			echo "hmmm"; \
		fi \
	done;

# mini hack
install: $(all_targets) $(install_targets) install-pdo-headers

/root/php-5.3.8/ext/phar/phar_path_check.c: /root/php-5.3.8/ext/phar/phar_path_check.re
	@(cd $(top_srcdir); $(RE2C) -b -o ext/phar/phar_path_check.c ext/phar/phar_path_check.re)

pharcmd: ext/phar/phar.php ext/phar/phar.phar

PHP_PHARCMD_SETTINGS = -d 'open_basedir=' -d 'output_buffering=0' -d 'memory_limit=-1' -d phar.readonly=0 -d 'safe_mode=0'
PHP_PHARCMD_EXECUTABLE = ` \
	if test -x "$(top_builddir)/$(SAPI_CLI_PATH)"; then \
		$(top_srcdir)/build/shtool echo -n -- "$(top_builddir)/$(SAPI_CLI_PATH) -n"; \
		if test "x$(PHP_MODULES)" != "x"; then \
		$(top_srcdir)/build/shtool echo -n -- " -d extension_dir=$(top_builddir)/modules"; \
		for i in bz2 zlib phar; do \
			if test -f "$(top_builddir)/modules/$$i.la"; then \
				. $(top_builddir)/modules/$$i.la; $(top_srcdir)/build/shtool echo -n -- " -d extension=$$dlname"; \
			fi; \
		done; \
		fi; \
	else \
		$(top_srcdir)/build/shtool echo -n -- "$(PHP_EXECUTABLE)"; \
	fi;`
PHP_PHARCMD_BANG = `$(top_srcdir)/build/shtool echo -n -- "$(INSTALL_ROOT)$(bindir)/$(program_prefix)php$(program_suffix)$(EXEEXT)";`

ext/phar/phar/phar.inc: /root/php-5.3.8/ext/phar/phar/phar.inc
	-@test -d ext/phar/phar || mkdir ext/phar/phar
	-@test -f ext/phar/phar/phar.inc || cp /root/php-5.3.8/ext/phar/phar/phar.inc ext/phar/phar/phar.inc

ext/phar/phar.php: /root/php-5.3.8/ext/phar/build_precommand.php /root/php-5.3.8/ext/phar/phar/*.inc /root/php-5.3.8/ext/phar/phar/*.php $(SAPI_CLI_PATH)
	-@echo "Generating phar.php"
	@$(PHP_PHARCMD_EXECUTABLE) $(PHP_PHARCMD_SETTINGS) /root/php-5.3.8/ext/phar/build_precommand.php > ext/phar/phar.php

ext/phar/phar.phar: ext/phar/phar.php ext/phar/phar/phar.inc /root/php-5.3.8/ext/phar/phar/*.inc /root/php-5.3.8/ext/phar/phar/*.php $(SAPI_CLI_PATH)
	-@echo "Generating phar.phar"
	-@rm -f ext/phar/phar.phar
	-@rm -f /root/php-5.3.8/ext/phar/phar.phar
	@$(PHP_PHARCMD_EXECUTABLE) $(PHP_PHARCMD_SETTINGS) ext/phar/phar.php pack -f ext/phar/phar.phar -a pharcommand -c auto -x \\.svn -p 0 -s /root/php-5.3.8/ext/phar/phar/phar.php -h sha1 -b "$(PHP_PHARCMD_BANG)"  /root/php-5.3.8/ext/phar/phar/
	-@chmod +x ext/phar/phar.phar

install-pharcmd: pharcmd
	-@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	$(INSTALL) ext/phar/phar.phar $(INSTALL_ROOT)$(bindir)
	-@rm -f $(INSTALL_ROOT)$(bindir)/phar
	$(LN_S) -f $(bindir)/phar.phar $(INSTALL_ROOT)$(bindir)/phar
/root/php-5.3.8/ext/sqlite/libsqlite/src/parse.c: /root/php-5.3.8/ext/sqlite/libsqlite/src/parse.y
	@$(LEMON) /root/php-5.3.8/ext/sqlite/libsqlite/src/parse.y 

/root/php-5.3.8/ext/standard/var_unserializer.c: /root/php-5.3.8/ext/standard/var_unserializer.re
	@(cd $(top_srcdir); $(RE2C) -b -o ext/standard/var_unserializer.c ext/standard/var_unserializer.re)

/root/php-5.3.8/ext/standard/url_scanner_ex.c: /root/php-5.3.8/ext/standard/url_scanner_ex.re
	@(cd $(top_srcdir); $(RE2C) -b -o ext/standard/url_scanner_ex.c	ext/standard/url_scanner_ex.re)

ext/standard/info.lo: ext/standard/../../main/build-defs.h

ext/standard/basic_functions.lo: $(top_srcdir)/Zend/zend_language_parser.h
$(top_srcdir)/Zend/zend_language_parser.c:
$(top_srcdir)/Zend/zend_language_scanner.c:
ext/tokenizer/tokenizer.lo: $(top_srcdir)/Zend/zend_language_parser.c $(top_srcdir)/Zend/zend_language_scanner.c

#
# Build environment install
#

phpincludedir = $(includedir)/php
phpbuilddir = $(libdir)/build

BUILD_FILES = \
	scripts/phpize.m4 \
	build/mkdep.awk \
	build/scan_makefile_in.awk \
	build/libtool.m4 \
	Makefile.global \
	acinclude.m4 \
	ltmain.sh \
	run-tests.php

BUILD_FILES_EXEC = \
	build/shtool \
	config.guess \
	config.sub

bin_SCRIPTS = phpize php-config
man_PAGES = phpize php-config

install-build:
	@echo "Installing build environment:     $(INSTALL_ROOT)$(phpbuilddir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(phpbuilddir) $(INSTALL_ROOT)$(bindir) && \
	(cd $(top_srcdir) && \
	$(INSTALL) $(BUILD_FILES_EXEC) $(INSTALL_ROOT)$(phpbuilddir) && \
	$(INSTALL_DATA) $(BUILD_FILES) $(INSTALL_ROOT)$(phpbuilddir))

install-programs: scripts/phpize scripts/php-config
	@echo "Installing helper programs:       $(INSTALL_ROOT)$(bindir)/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(bindir)
	@for prog in $(bin_SCRIPTS); do \
		echo "  program: $(program_prefix)$${prog}$(program_suffix)"; \
		$(INSTALL) -m 755 scripts/$${prog} $(INSTALL_ROOT)$(bindir)/$(program_prefix)$${prog}$(program_suffix); \
	done
	@echo "Installing man pages:             $(INSTALL_ROOT)$(mandir)/man1/"
	@$(mkinstalldirs) $(INSTALL_ROOT)$(mandir)/man1
	@for page in $(man_PAGES); do \
		echo "  page: $(program_prefix)$${page}$(program_suffix).1"; \
		$(INSTALL_DATA) scripts/man1/$${page}.1 $(INSTALL_ROOT)$(mandir)/man1/$(program_prefix)$${page}$(program_suffix).1; \
	done
	
scripts/phpize: /root/php-5.3.8/scripts/phpize.in $(top_builddir)/config.status
	(CONFIG_FILES=$@ CONFIG_HEADERS= $(top_builddir)/config.status)

scripts/php-config: /root/php-5.3.8/scripts/php-config.in $(top_builddir)/config.status
	(CONFIG_FILES=$@ CONFIG_HEADERS= $(top_builddir)/config.status)

#
# Zend
#

Zend/zend_language_scanner.lo: /root/php-5.3.8/Zend/zend_language_parser.h
Zend/zend_ini_scanner.lo: /root/php-5.3.8/Zend/zend_ini_parser.h

/root/php-5.3.8/Zend/zend_language_scanner.c: /root/php-5.3.8/Zend/zend_language_scanner.l
	@(cd $(top_srcdir); $(RE2C) $(RE2C_FLAGS) --case-inverted -cbdFt Zend/zend_language_scanner_defs.h -oZend/zend_language_scanner.c Zend/zend_language_scanner.l)

/root/php-5.3.8/Zend/zend_language_parser.h: /root/php-5.3.8/Zend/zend_language_parser.c
/root/php-5.3.8/Zend/zend_language_parser.c: /root/php-5.3.8/Zend/zend_language_parser.y
	@$(YACC) -p zend -v -d /root/php-5.3.8/Zend/zend_language_parser.y -o $@

/root/php-5.3.8/Zend/zend_ini_parser.h: /root/php-5.3.8/Zend/zend_ini_parser.c
/root/php-5.3.8/Zend/zend_ini_parser.c: /root/php-5.3.8/Zend/zend_ini_parser.y
	@$(YACC) -p ini_ -v -d /root/php-5.3.8/Zend/zend_ini_parser.y -o $@

/root/php-5.3.8/Zend/zend_ini_scanner.c: /root/php-5.3.8/Zend/zend_ini_scanner.l
	@(cd $(top_srcdir); $(RE2C) $(RE2C_FLAGS) --case-inverted -cbdFt Zend/zend_ini_scanner_defs.h -oZend/zend_ini_scanner.c Zend/zend_ini_scanner.l)

Zend/zend_indent.lo Zend/zend_highlight.lo Zend/zend_compile.lo: /root/php-5.3.8/Zend/zend_language_parser.h
Zend/zend_execute.lo: /root/php-5.3.8/Zend/zend_vm_execute.h /root/php-5.3.8/Zend/zend_vm_opcodes.h
sapi/uwsgi/php_plugin.lo: /root/php-5.3.8/sapi/uwsgi/php_plugin.c
	$(LIBTOOL) --mode=compile $(CC) -O2 -Wall -Werror -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 -fno-strict-aliasing -Wextra -Wno-unused-parameter -Wno-missing-field-initializers -DUWSGI_BUILD_DATE="\"20 December 2011 10:04:53\"" -DUWSGI_HAS_IFADDRS -DUWSGI_LOCK_USE_MUTEX -DUWSGI_EVENT_USE_EPOLL -DUWSGI_EVENT_TIMER_USE_TIMERFD -DUWSGI_EVENT_FILEMONITOR_USE_INOTIFY -DUWSGI_EMBEDDED -DUWSGI_UDP  -DUWSGI_PCRE -DUWSGI_UUID -DUWSGI_VERSION="\"1.0-dev-1797\"" -DUWSGI_VERSION_BASE="1" -DUWSGI_VERSION_MAJOR="0" -DUWSGI_VERSION_MINOR="0" -DUWSGI_VERSION_REVISION="0" -DUWSGI_VERSION_CUSTOM="\"dev-1797\"" -DUWSGI_ASYNC -DUWSGI_MULTICAST -DUWSGI_MINTERPRETERS -DUWSGI_INI -DUWSGI_YAML -DUWSGI_LIBYAML -DUWSGI_LDAP -DUWSGI_ZEROMQ -DUWSGI_SNMP -DUWSGI_THREADING -DUWSGI_SENDFILE -I/usr/include/libxml2 -DUWSGI_XML -DUWSGI_XML_LIBXML2 -DUWSGI_SQLITE3 -DUWSGI_PLUGIN_DIR=\".\" -DUWSGI_SPOOLER -DUWSGI_DECLARE_EMBEDDED_PLUGINS="UDEP(python);UDEP(ping);UDEP(cache);UDEP(nagios);UDEP(rrdtool);UDEP(carbon);UDEP(rpc);UDEP(fastrouter);UDEP(http);UDEP(ugreen);UDEP(signal);UDEP(syslog);UDEP(rsyslog);UDEP(logsocket);" -DUWSGI_LOAD_EMBEDDED_PLUGINS="ULEP(python);ULEP(ping);ULEP(cache);ULEP(nagios);ULEP(rrdtool);ULEP(carbon);ULEP(rpc);ULEP(fastrouter);ULEP(http);ULEP(ugreen);ULEP(signal);ULEP(syslog);ULEP(rsyslog);ULEP(logsocket);" -Isapi/uwsgi/ -I/root/php-5.3.8/sapi/uwsgi/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/sapi/uwsgi/php_plugin.c -o sapi/uwsgi/php_plugin.lo 
ext/date/php_date.lo: /root/php-5.3.8/ext/date/php_date.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/php_date.c -o ext/date/php_date.lo 
ext/date/lib/astro.lo: /root/php-5.3.8/ext/date/lib/astro.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/astro.c -o ext/date/lib/astro.lo 
ext/date/lib/dow.lo: /root/php-5.3.8/ext/date/lib/dow.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/dow.c -o ext/date/lib/dow.lo 
ext/date/lib/parse_date.lo: /root/php-5.3.8/ext/date/lib/parse_date.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/parse_date.c -o ext/date/lib/parse_date.lo 
ext/date/lib/parse_tz.lo: /root/php-5.3.8/ext/date/lib/parse_tz.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/parse_tz.c -o ext/date/lib/parse_tz.lo 
ext/date/lib/timelib.lo: /root/php-5.3.8/ext/date/lib/timelib.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/timelib.c -o ext/date/lib/timelib.lo 
ext/date/lib/tm2unixtime.lo: /root/php-5.3.8/ext/date/lib/tm2unixtime.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/tm2unixtime.c -o ext/date/lib/tm2unixtime.lo 
ext/date/lib/unixtime2tm.lo: /root/php-5.3.8/ext/date/lib/unixtime2tm.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/unixtime2tm.c -o ext/date/lib/unixtime2tm.lo 
ext/date/lib/parse_iso_intervals.lo: /root/php-5.3.8/ext/date/lib/parse_iso_intervals.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/parse_iso_intervals.c -o ext/date/lib/parse_iso_intervals.lo 
ext/date/lib/interval.lo: /root/php-5.3.8/ext/date/lib/interval.c
	$(LIBTOOL) --mode=compile $(CC) -Iext/date/lib -Iext/date/ -I/root/php-5.3.8/ext/date/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/date/lib/interval.c -o ext/date/lib/interval.lo 
ext/ereg/ereg.lo: /root/php-5.3.8/ext/ereg/ereg.c
	$(LIBTOOL) --mode=compile $(CC) -Dregexec=php_regexec -Dregerror=php_regerror -Dregfree=php_regfree -Dregcomp=php_regcomp -Iext/ereg/ -I/root/php-5.3.8/ext/ereg/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/ereg/ereg.c -o ext/ereg/ereg.lo 
ext/ereg/regex/regcomp.lo: /root/php-5.3.8/ext/ereg/regex/regcomp.c
	$(LIBTOOL) --mode=compile $(CC) -Dregexec=php_regexec -Dregerror=php_regerror -Dregfree=php_regfree -Dregcomp=php_regcomp -Iext/ereg/ -I/root/php-5.3.8/ext/ereg/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/ereg/regex/regcomp.c -o ext/ereg/regex/regcomp.lo 
ext/ereg/regex/regexec.lo: /root/php-5.3.8/ext/ereg/regex/regexec.c
	$(LIBTOOL) --mode=compile $(CC) -Dregexec=php_regexec -Dregerror=php_regerror -Dregfree=php_regfree -Dregcomp=php_regcomp -Iext/ereg/ -I/root/php-5.3.8/ext/ereg/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/ereg/regex/regexec.c -o ext/ereg/regex/regexec.lo 
ext/ereg/regex/regerror.lo: /root/php-5.3.8/ext/ereg/regex/regerror.c
	$(LIBTOOL) --mode=compile $(CC) -Dregexec=php_regexec -Dregerror=php_regerror -Dregfree=php_regfree -Dregcomp=php_regcomp -Iext/ereg/ -I/root/php-5.3.8/ext/ereg/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/ereg/regex/regerror.c -o ext/ereg/regex/regerror.lo 
ext/ereg/regex/regfree.lo: /root/php-5.3.8/ext/ereg/regex/regfree.c
	$(LIBTOOL) --mode=compile $(CC) -Dregexec=php_regexec -Dregerror=php_regerror -Dregfree=php_regfree -Dregcomp=php_regcomp -Iext/ereg/ -I/root/php-5.3.8/ext/ereg/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/ereg/regex/regfree.c -o ext/ereg/regex/regfree.lo 
ext/libxml/libxml.lo: /root/php-5.3.8/ext/libxml/libxml.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/libxml/ -I/root/php-5.3.8/ext/libxml/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/libxml/libxml.c -o ext/libxml/libxml.lo 
ext/pcre/pcrelib/pcre_chartables.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_chartables.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_chartables.c -o ext/pcre/pcrelib/pcre_chartables.lo 
ext/pcre/pcrelib/pcre_ucd.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_ucd.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_ucd.c -o ext/pcre/pcrelib/pcre_ucd.lo 
ext/pcre/pcrelib/pcre_compile.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_compile.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_compile.c -o ext/pcre/pcrelib/pcre_compile.lo 
ext/pcre/pcrelib/pcre_config.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_config.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_config.c -o ext/pcre/pcrelib/pcre_config.lo 
ext/pcre/pcrelib/pcre_exec.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_exec.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_exec.c -o ext/pcre/pcrelib/pcre_exec.lo 
ext/pcre/pcrelib/pcre_fullinfo.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_fullinfo.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_fullinfo.c -o ext/pcre/pcrelib/pcre_fullinfo.lo 
ext/pcre/pcrelib/pcre_get.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_get.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_get.c -o ext/pcre/pcrelib/pcre_get.lo 
ext/pcre/pcrelib/pcre_globals.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_globals.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_globals.c -o ext/pcre/pcrelib/pcre_globals.lo 
ext/pcre/pcrelib/pcre_info.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_info.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_info.c -o ext/pcre/pcrelib/pcre_info.lo 
ext/pcre/pcrelib/pcre_maketables.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_maketables.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_maketables.c -o ext/pcre/pcrelib/pcre_maketables.lo 
ext/pcre/pcrelib/pcre_newline.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_newline.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_newline.c -o ext/pcre/pcrelib/pcre_newline.lo 
ext/pcre/pcrelib/pcre_ord2utf8.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_ord2utf8.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_ord2utf8.c -o ext/pcre/pcrelib/pcre_ord2utf8.lo 
ext/pcre/pcrelib/pcre_refcount.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_refcount.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_refcount.c -o ext/pcre/pcrelib/pcre_refcount.lo 
ext/pcre/pcrelib/pcre_study.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_study.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_study.c -o ext/pcre/pcrelib/pcre_study.lo 
ext/pcre/pcrelib/pcre_tables.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_tables.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_tables.c -o ext/pcre/pcrelib/pcre_tables.lo 
ext/pcre/pcrelib/pcre_try_flipped.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_try_flipped.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_try_flipped.c -o ext/pcre/pcrelib/pcre_try_flipped.lo 
ext/pcre/pcrelib/pcre_valid_utf8.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_valid_utf8.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_valid_utf8.c -o ext/pcre/pcrelib/pcre_valid_utf8.lo 
ext/pcre/pcrelib/pcre_version.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_version.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_version.c -o ext/pcre/pcrelib/pcre_version.lo 
ext/pcre/pcrelib/pcre_xclass.lo: /root/php-5.3.8/ext/pcre/pcrelib/pcre_xclass.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/pcrelib/pcre_xclass.c -o ext/pcre/pcrelib/pcre_xclass.lo 
ext/pcre/php_pcre.lo: /root/php-5.3.8/ext/pcre/php_pcre.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/pcre/pcrelib -Iext/pcre/ -I/root/php-5.3.8/ext/pcre/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pcre/php_pcre.c -o ext/pcre/php_pcre.lo 
ext/sqlite3/sqlite3.lo: /root/php-5.3.8/ext/sqlite3/sqlite3.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite3/libsqlite -DSQLITE_ENABLE_FTS3=1 -DSQLITE_CORE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_THREADSAFE=0  -Iext/sqlite3/ -I/root/php-5.3.8/ext/sqlite3/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite3/sqlite3.c -o ext/sqlite3/sqlite3.lo 
ext/sqlite3/libsqlite/sqlite3.lo: /root/php-5.3.8/ext/sqlite3/libsqlite/sqlite3.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite3/libsqlite -DSQLITE_ENABLE_FTS3=1 -DSQLITE_CORE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_THREADSAFE=0  -Iext/sqlite3/ -I/root/php-5.3.8/ext/sqlite3/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite3/libsqlite/sqlite3.c -o ext/sqlite3/libsqlite/sqlite3.lo 
ext/ctype/ctype.lo: /root/php-5.3.8/ext/ctype/ctype.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/ctype/ -I/root/php-5.3.8/ext/ctype/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/ctype/ctype.c -o ext/ctype/ctype.lo 
ext/dom/php_dom.lo: /root/php-5.3.8/ext/dom/php_dom.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/php_dom.c -o ext/dom/php_dom.lo 
ext/dom/attr.lo: /root/php-5.3.8/ext/dom/attr.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/attr.c -o ext/dom/attr.lo 
ext/dom/document.lo: /root/php-5.3.8/ext/dom/document.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/document.c -o ext/dom/document.lo 
ext/dom/domerrorhandler.lo: /root/php-5.3.8/ext/dom/domerrorhandler.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domerrorhandler.c -o ext/dom/domerrorhandler.lo 
ext/dom/domstringlist.lo: /root/php-5.3.8/ext/dom/domstringlist.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domstringlist.c -o ext/dom/domstringlist.lo 
ext/dom/domexception.lo: /root/php-5.3.8/ext/dom/domexception.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domexception.c -o ext/dom/domexception.lo 
ext/dom/namelist.lo: /root/php-5.3.8/ext/dom/namelist.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/namelist.c -o ext/dom/namelist.lo 
ext/dom/processinginstruction.lo: /root/php-5.3.8/ext/dom/processinginstruction.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/processinginstruction.c -o ext/dom/processinginstruction.lo 
ext/dom/cdatasection.lo: /root/php-5.3.8/ext/dom/cdatasection.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/cdatasection.c -o ext/dom/cdatasection.lo 
ext/dom/documentfragment.lo: /root/php-5.3.8/ext/dom/documentfragment.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/documentfragment.c -o ext/dom/documentfragment.lo 
ext/dom/domimplementation.lo: /root/php-5.3.8/ext/dom/domimplementation.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domimplementation.c -o ext/dom/domimplementation.lo 
ext/dom/element.lo: /root/php-5.3.8/ext/dom/element.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/element.c -o ext/dom/element.lo 
ext/dom/node.lo: /root/php-5.3.8/ext/dom/node.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/node.c -o ext/dom/node.lo 
ext/dom/string_extend.lo: /root/php-5.3.8/ext/dom/string_extend.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/string_extend.c -o ext/dom/string_extend.lo 
ext/dom/characterdata.lo: /root/php-5.3.8/ext/dom/characterdata.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/characterdata.c -o ext/dom/characterdata.lo 
ext/dom/documenttype.lo: /root/php-5.3.8/ext/dom/documenttype.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/documenttype.c -o ext/dom/documenttype.lo 
ext/dom/domimplementationlist.lo: /root/php-5.3.8/ext/dom/domimplementationlist.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domimplementationlist.c -o ext/dom/domimplementationlist.lo 
ext/dom/entity.lo: /root/php-5.3.8/ext/dom/entity.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/entity.c -o ext/dom/entity.lo 
ext/dom/nodelist.lo: /root/php-5.3.8/ext/dom/nodelist.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/nodelist.c -o ext/dom/nodelist.lo 
ext/dom/text.lo: /root/php-5.3.8/ext/dom/text.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/text.c -o ext/dom/text.lo 
ext/dom/comment.lo: /root/php-5.3.8/ext/dom/comment.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/comment.c -o ext/dom/comment.lo 
ext/dom/domconfiguration.lo: /root/php-5.3.8/ext/dom/domconfiguration.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domconfiguration.c -o ext/dom/domconfiguration.lo 
ext/dom/domimplementationsource.lo: /root/php-5.3.8/ext/dom/domimplementationsource.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domimplementationsource.c -o ext/dom/domimplementationsource.lo 
ext/dom/entityreference.lo: /root/php-5.3.8/ext/dom/entityreference.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/entityreference.c -o ext/dom/entityreference.lo 
ext/dom/notation.lo: /root/php-5.3.8/ext/dom/notation.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/notation.c -o ext/dom/notation.lo 
ext/dom/xpath.lo: /root/php-5.3.8/ext/dom/xpath.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/xpath.c -o ext/dom/xpath.lo 
ext/dom/dom_iterators.lo: /root/php-5.3.8/ext/dom/dom_iterators.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/dom_iterators.c -o ext/dom/dom_iterators.lo 
ext/dom/typeinfo.lo: /root/php-5.3.8/ext/dom/typeinfo.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/typeinfo.c -o ext/dom/typeinfo.lo 
ext/dom/domerror.lo: /root/php-5.3.8/ext/dom/domerror.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domerror.c -o ext/dom/domerror.lo 
ext/dom/domlocator.lo: /root/php-5.3.8/ext/dom/domlocator.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/domlocator.c -o ext/dom/domlocator.lo 
ext/dom/namednodemap.lo: /root/php-5.3.8/ext/dom/namednodemap.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/namednodemap.c -o ext/dom/namednodemap.lo 
ext/dom/userdatahandler.lo: /root/php-5.3.8/ext/dom/userdatahandler.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/dom/ -I/root/php-5.3.8/ext/dom/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/dom/userdatahandler.c -o ext/dom/userdatahandler.lo 
ext/fileinfo/fileinfo.lo: /root/php-5.3.8/ext/fileinfo/fileinfo.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/fileinfo.c -o ext/fileinfo/fileinfo.lo 
ext/fileinfo/libmagic/apprentice.lo: /root/php-5.3.8/ext/fileinfo/libmagic/apprentice.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/apprentice.c -o ext/fileinfo/libmagic/apprentice.lo 
ext/fileinfo/libmagic/apptype.lo: /root/php-5.3.8/ext/fileinfo/libmagic/apptype.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/apptype.c -o ext/fileinfo/libmagic/apptype.lo 
ext/fileinfo/libmagic/ascmagic.lo: /root/php-5.3.8/ext/fileinfo/libmagic/ascmagic.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/ascmagic.c -o ext/fileinfo/libmagic/ascmagic.lo 
ext/fileinfo/libmagic/cdf.lo: /root/php-5.3.8/ext/fileinfo/libmagic/cdf.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/cdf.c -o ext/fileinfo/libmagic/cdf.lo 
ext/fileinfo/libmagic/cdf_time.lo: /root/php-5.3.8/ext/fileinfo/libmagic/cdf_time.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/cdf_time.c -o ext/fileinfo/libmagic/cdf_time.lo 
ext/fileinfo/libmagic/compress.lo: /root/php-5.3.8/ext/fileinfo/libmagic/compress.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/compress.c -o ext/fileinfo/libmagic/compress.lo 
ext/fileinfo/libmagic/encoding.lo: /root/php-5.3.8/ext/fileinfo/libmagic/encoding.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/encoding.c -o ext/fileinfo/libmagic/encoding.lo 
ext/fileinfo/libmagic/fsmagic.lo: /root/php-5.3.8/ext/fileinfo/libmagic/fsmagic.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/fsmagic.c -o ext/fileinfo/libmagic/fsmagic.lo 
ext/fileinfo/libmagic/funcs.lo: /root/php-5.3.8/ext/fileinfo/libmagic/funcs.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/funcs.c -o ext/fileinfo/libmagic/funcs.lo 
ext/fileinfo/libmagic/is_tar.lo: /root/php-5.3.8/ext/fileinfo/libmagic/is_tar.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/is_tar.c -o ext/fileinfo/libmagic/is_tar.lo 
ext/fileinfo/libmagic/magic.lo: /root/php-5.3.8/ext/fileinfo/libmagic/magic.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/magic.c -o ext/fileinfo/libmagic/magic.lo 
ext/fileinfo/libmagic/print.lo: /root/php-5.3.8/ext/fileinfo/libmagic/print.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/print.c -o ext/fileinfo/libmagic/print.lo 
ext/fileinfo/libmagic/readcdf.lo: /root/php-5.3.8/ext/fileinfo/libmagic/readcdf.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/readcdf.c -o ext/fileinfo/libmagic/readcdf.lo 
ext/fileinfo/libmagic/readelf.lo: /root/php-5.3.8/ext/fileinfo/libmagic/readelf.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/readelf.c -o ext/fileinfo/libmagic/readelf.lo 
ext/fileinfo/libmagic/softmagic.lo: /root/php-5.3.8/ext/fileinfo/libmagic/softmagic.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/fileinfo/libmagic -Iext/fileinfo/ -I/root/php-5.3.8/ext/fileinfo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/fileinfo/libmagic/softmagic.c -o ext/fileinfo/libmagic/softmagic.lo 
ext/filter/filter.lo: /root/php-5.3.8/ext/filter/filter.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/filter/ -I/root/php-5.3.8/ext/filter/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/filter/filter.c -o ext/filter/filter.lo 
ext/filter/sanitizing_filters.lo: /root/php-5.3.8/ext/filter/sanitizing_filters.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/filter/ -I/root/php-5.3.8/ext/filter/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/filter/sanitizing_filters.c -o ext/filter/sanitizing_filters.lo 
ext/filter/logical_filters.lo: /root/php-5.3.8/ext/filter/logical_filters.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/filter/ -I/root/php-5.3.8/ext/filter/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/filter/logical_filters.c -o ext/filter/logical_filters.lo 
ext/filter/callback_filter.lo: /root/php-5.3.8/ext/filter/callback_filter.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/filter/ -I/root/php-5.3.8/ext/filter/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/filter/callback_filter.c -o ext/filter/callback_filter.lo 
ext/hash/hash.lo: /root/php-5.3.8/ext/hash/hash.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash.c -o ext/hash/hash.lo 
ext/hash/hash_md.lo: /root/php-5.3.8/ext/hash/hash_md.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_md.c -o ext/hash/hash_md.lo 
ext/hash/hash_sha.lo: /root/php-5.3.8/ext/hash/hash_sha.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_sha.c -o ext/hash/hash_sha.lo 
ext/hash/hash_ripemd.lo: /root/php-5.3.8/ext/hash/hash_ripemd.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_ripemd.c -o ext/hash/hash_ripemd.lo 
ext/hash/hash_haval.lo: /root/php-5.3.8/ext/hash/hash_haval.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_haval.c -o ext/hash/hash_haval.lo 
ext/hash/hash_tiger.lo: /root/php-5.3.8/ext/hash/hash_tiger.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_tiger.c -o ext/hash/hash_tiger.lo 
ext/hash/hash_gost.lo: /root/php-5.3.8/ext/hash/hash_gost.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_gost.c -o ext/hash/hash_gost.lo 
ext/hash/hash_snefru.lo: /root/php-5.3.8/ext/hash/hash_snefru.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_snefru.c -o ext/hash/hash_snefru.lo 
ext/hash/hash_whirlpool.lo: /root/php-5.3.8/ext/hash/hash_whirlpool.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_whirlpool.c -o ext/hash/hash_whirlpool.lo 
ext/hash/hash_adler32.lo: /root/php-5.3.8/ext/hash/hash_adler32.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_adler32.c -o ext/hash/hash_adler32.lo 
ext/hash/hash_crc32.lo: /root/php-5.3.8/ext/hash/hash_crc32.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_crc32.c -o ext/hash/hash_crc32.lo 
ext/hash/hash_salsa.lo: /root/php-5.3.8/ext/hash/hash_salsa.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/hash/ -I/root/php-5.3.8/ext/hash/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/hash/hash_salsa.c -o ext/hash/hash_salsa.lo 
ext/iconv/iconv.lo: /root/php-5.3.8/ext/iconv/iconv.c
	$(LIBTOOL) --mode=compile $(CC) -I"/usr/include" -Iext/iconv/ -I/root/php-5.3.8/ext/iconv/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/iconv/iconv.c -o ext/iconv/iconv.lo 
ext/json/json.lo: /root/php-5.3.8/ext/json/json.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/json/ -I/root/php-5.3.8/ext/json/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/json/json.c -o ext/json/json.lo 
ext/json/utf8_to_utf16.lo: /root/php-5.3.8/ext/json/utf8_to_utf16.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/json/ -I/root/php-5.3.8/ext/json/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/json/utf8_to_utf16.c -o ext/json/utf8_to_utf16.lo 
ext/json/utf8_decode.lo: /root/php-5.3.8/ext/json/utf8_decode.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/json/ -I/root/php-5.3.8/ext/json/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/json/utf8_decode.c -o ext/json/utf8_decode.lo 
ext/json/JSON_parser.lo: /root/php-5.3.8/ext/json/JSON_parser.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/json/ -I/root/php-5.3.8/ext/json/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/json/JSON_parser.c -o ext/json/JSON_parser.lo 
ext/mysql/php_mysql.lo: /root/php-5.3.8/ext/mysql/php_mysql.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/mysql/ -I/root/php-5.3.8/ext/mysql/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/mysql/php_mysql.c -o ext/mysql/php_mysql.lo 
ext/pdo/pdo.lo: /root/php-5.3.8/ext/pdo/pdo.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/pdo/ -I/root/php-5.3.8/ext/pdo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo/pdo.c -o ext/pdo/pdo.lo 
ext/pdo/pdo_dbh.lo: /root/php-5.3.8/ext/pdo/pdo_dbh.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/pdo/ -I/root/php-5.3.8/ext/pdo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo/pdo_dbh.c -o ext/pdo/pdo_dbh.lo 
ext/pdo/pdo_stmt.lo: /root/php-5.3.8/ext/pdo/pdo_stmt.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/pdo/ -I/root/php-5.3.8/ext/pdo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo/pdo_stmt.c -o ext/pdo/pdo_stmt.lo 
ext/pdo/pdo_sql_parser.lo: /root/php-5.3.8/ext/pdo/pdo_sql_parser.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/pdo/ -I/root/php-5.3.8/ext/pdo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo/pdo_sql_parser.c -o ext/pdo/pdo_sql_parser.lo 
ext/pdo/pdo_sqlstate.lo: /root/php-5.3.8/ext/pdo/pdo_sqlstate.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/pdo/ -I/root/php-5.3.8/ext/pdo/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo/pdo_sqlstate.c -o ext/pdo/pdo_sqlstate.lo 
ext/pdo_sqlite/pdo_sqlite.lo: /root/php-5.3.8/ext/pdo_sqlite/pdo_sqlite.c
	$(LIBTOOL) --mode=compile $(CC) -DPDO_SQLITE_BUNDLED=1 -DSQLITE_ENABLE_FTS3=1 -DSQLITE_CORE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_THREADSAFE=0 -I/root/php-5.3.8/ext -Iext/pdo_sqlite/ -I/root/php-5.3.8/ext/pdo_sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo_sqlite/pdo_sqlite.c -o ext/pdo_sqlite/pdo_sqlite.lo 
ext/pdo_sqlite/sqlite_driver.lo: /root/php-5.3.8/ext/pdo_sqlite/sqlite_driver.c
	$(LIBTOOL) --mode=compile $(CC) -DPDO_SQLITE_BUNDLED=1 -DSQLITE_ENABLE_FTS3=1 -DSQLITE_CORE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_THREADSAFE=0 -I/root/php-5.3.8/ext -Iext/pdo_sqlite/ -I/root/php-5.3.8/ext/pdo_sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo_sqlite/sqlite_driver.c -o ext/pdo_sqlite/sqlite_driver.lo 
ext/pdo_sqlite/sqlite_statement.lo: /root/php-5.3.8/ext/pdo_sqlite/sqlite_statement.c
	$(LIBTOOL) --mode=compile $(CC) -DPDO_SQLITE_BUNDLED=1 -DSQLITE_ENABLE_FTS3=1 -DSQLITE_CORE=1 -DSQLITE_ENABLE_COLUMN_METADATA=1 -DSQLITE_THREADSAFE=0 -I/root/php-5.3.8/ext -Iext/pdo_sqlite/ -I/root/php-5.3.8/ext/pdo_sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/pdo_sqlite/sqlite_statement.c -o ext/pdo_sqlite/sqlite_statement.lo 
ext/phar/util.lo: /root/php-5.3.8/ext/phar/util.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/util.c -o ext/phar/util.lo 
ext/phar/tar.lo: /root/php-5.3.8/ext/phar/tar.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/tar.c -o ext/phar/tar.lo 
ext/phar/zip.lo: /root/php-5.3.8/ext/phar/zip.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/zip.c -o ext/phar/zip.lo 
ext/phar/stream.lo: /root/php-5.3.8/ext/phar/stream.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/stream.c -o ext/phar/stream.lo 
ext/phar/func_interceptors.lo: /root/php-5.3.8/ext/phar/func_interceptors.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/func_interceptors.c -o ext/phar/func_interceptors.lo 
ext/phar/dirstream.lo: /root/php-5.3.8/ext/phar/dirstream.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/dirstream.c -o ext/phar/dirstream.lo 
ext/phar/phar.lo: /root/php-5.3.8/ext/phar/phar.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/phar.c -o ext/phar/phar.lo 
ext/phar/phar_object.lo: /root/php-5.3.8/ext/phar/phar_object.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/phar_object.c -o ext/phar/phar_object.lo 
ext/phar/phar_path_check.lo: /root/php-5.3.8/ext/phar/phar_path_check.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/phar/ -I/root/php-5.3.8/ext/phar/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/phar/phar_path_check.c -o ext/phar/phar_path_check.lo 
ext/posix/posix.lo: /root/php-5.3.8/ext/posix/posix.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/posix/ -I/root/php-5.3.8/ext/posix/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/posix/posix.c -o ext/posix/posix.lo 
ext/reflection/php_reflection.lo: /root/php-5.3.8/ext/reflection/php_reflection.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/reflection/ -I/root/php-5.3.8/ext/reflection/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/reflection/php_reflection.c -o ext/reflection/php_reflection.lo 
ext/session/session.lo: /root/php-5.3.8/ext/session/session.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/session/ -I/root/php-5.3.8/ext/session/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/session/session.c -o ext/session/session.lo 
ext/session/mod_files.lo: /root/php-5.3.8/ext/session/mod_files.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/session/ -I/root/php-5.3.8/ext/session/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/session/mod_files.c -o ext/session/mod_files.lo 
ext/session/mod_mm.lo: /root/php-5.3.8/ext/session/mod_mm.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/session/ -I/root/php-5.3.8/ext/session/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/session/mod_mm.c -o ext/session/mod_mm.lo 
ext/session/mod_user.lo: /root/php-5.3.8/ext/session/mod_user.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/session/ -I/root/php-5.3.8/ext/session/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/session/mod_user.c -o ext/session/mod_user.lo 
ext/simplexml/simplexml.lo: /root/php-5.3.8/ext/simplexml/simplexml.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/simplexml/ -I/root/php-5.3.8/ext/simplexml/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/simplexml/simplexml.c -o ext/simplexml/simplexml.lo 
ext/simplexml/sxe.lo: /root/php-5.3.8/ext/simplexml/sxe.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/simplexml/ -I/root/php-5.3.8/ext/simplexml/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/simplexml/sxe.c -o ext/simplexml/sxe.lo 
ext/spl/php_spl.lo: /root/php-5.3.8/ext/spl/php_spl.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/php_spl.c -o ext/spl/php_spl.lo 
ext/spl/spl_functions.lo: /root/php-5.3.8/ext/spl/spl_functions.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_functions.c -o ext/spl/spl_functions.lo 
ext/spl/spl_engine.lo: /root/php-5.3.8/ext/spl/spl_engine.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_engine.c -o ext/spl/spl_engine.lo 
ext/spl/spl_iterators.lo: /root/php-5.3.8/ext/spl/spl_iterators.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_iterators.c -o ext/spl/spl_iterators.lo 
ext/spl/spl_array.lo: /root/php-5.3.8/ext/spl/spl_array.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_array.c -o ext/spl/spl_array.lo 
ext/spl/spl_directory.lo: /root/php-5.3.8/ext/spl/spl_directory.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_directory.c -o ext/spl/spl_directory.lo 
ext/spl/spl_exceptions.lo: /root/php-5.3.8/ext/spl/spl_exceptions.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_exceptions.c -o ext/spl/spl_exceptions.lo 
ext/spl/spl_observer.lo: /root/php-5.3.8/ext/spl/spl_observer.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_observer.c -o ext/spl/spl_observer.lo 
ext/spl/spl_dllist.lo: /root/php-5.3.8/ext/spl/spl_dllist.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_dllist.c -o ext/spl/spl_dllist.lo 
ext/spl/spl_heap.lo: /root/php-5.3.8/ext/spl/spl_heap.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_heap.c -o ext/spl/spl_heap.lo 
ext/spl/spl_fixedarray.lo: /root/php-5.3.8/ext/spl/spl_fixedarray.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/spl/ -I/root/php-5.3.8/ext/spl/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/spl/spl_fixedarray.c -o ext/spl/spl_fixedarray.lo 
ext/sqlite/sqlite.lo: /root/php-5.3.8/ext/sqlite/sqlite.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/sqlite.c -o ext/sqlite/sqlite.lo 
ext/sqlite/sess_sqlite.lo: /root/php-5.3.8/ext/sqlite/sess_sqlite.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/sess_sqlite.c -o ext/sqlite/sess_sqlite.lo 
ext/sqlite/pdo_sqlite2.lo: /root/php-5.3.8/ext/sqlite/pdo_sqlite2.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/pdo_sqlite2.c -o ext/sqlite/pdo_sqlite2.lo 
ext/sqlite/libsqlite/src/opcodes.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/opcodes.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/opcodes.c -o ext/sqlite/libsqlite/src/opcodes.lo 
ext/sqlite/libsqlite/src/parse.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/parse.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/parse.c -o ext/sqlite/libsqlite/src/parse.lo 
ext/sqlite/libsqlite/src/encode.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/encode.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/encode.c -o ext/sqlite/libsqlite/src/encode.lo 
ext/sqlite/libsqlite/src/auth.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/auth.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/auth.c -o ext/sqlite/libsqlite/src/auth.lo 
ext/sqlite/libsqlite/src/btree.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/btree.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/btree.c -o ext/sqlite/libsqlite/src/btree.lo 
ext/sqlite/libsqlite/src/build.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/build.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/build.c -o ext/sqlite/libsqlite/src/build.lo 
ext/sqlite/libsqlite/src/delete.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/delete.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/delete.c -o ext/sqlite/libsqlite/src/delete.lo 
ext/sqlite/libsqlite/src/expr.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/expr.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/expr.c -o ext/sqlite/libsqlite/src/expr.lo 
ext/sqlite/libsqlite/src/func.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/func.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/func.c -o ext/sqlite/libsqlite/src/func.lo 
ext/sqlite/libsqlite/src/hash.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/hash.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/hash.c -o ext/sqlite/libsqlite/src/hash.lo 
ext/sqlite/libsqlite/src/insert.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/insert.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/insert.c -o ext/sqlite/libsqlite/src/insert.lo 
ext/sqlite/libsqlite/src/main.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/main.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/main.c -o ext/sqlite/libsqlite/src/main.lo 
ext/sqlite/libsqlite/src/os.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/os.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/os.c -o ext/sqlite/libsqlite/src/os.lo 
ext/sqlite/libsqlite/src/pager.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/pager.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/pager.c -o ext/sqlite/libsqlite/src/pager.lo 
ext/sqlite/libsqlite/src/printf.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/printf.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/printf.c -o ext/sqlite/libsqlite/src/printf.lo 
ext/sqlite/libsqlite/src/random.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/random.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/random.c -o ext/sqlite/libsqlite/src/random.lo 
ext/sqlite/libsqlite/src/select.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/select.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/select.c -o ext/sqlite/libsqlite/src/select.lo 
ext/sqlite/libsqlite/src/table.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/table.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/table.c -o ext/sqlite/libsqlite/src/table.lo 
ext/sqlite/libsqlite/src/tokenize.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/tokenize.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/tokenize.c -o ext/sqlite/libsqlite/src/tokenize.lo 
ext/sqlite/libsqlite/src/update.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/update.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/update.c -o ext/sqlite/libsqlite/src/update.lo 
ext/sqlite/libsqlite/src/util.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/util.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/util.c -o ext/sqlite/libsqlite/src/util.lo 
ext/sqlite/libsqlite/src/vdbe.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/vdbe.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/vdbe.c -o ext/sqlite/libsqlite/src/vdbe.lo 
ext/sqlite/libsqlite/src/attach.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/attach.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/attach.c -o ext/sqlite/libsqlite/src/attach.lo 
ext/sqlite/libsqlite/src/btree_rb.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/btree_rb.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/btree_rb.c -o ext/sqlite/libsqlite/src/btree_rb.lo 
ext/sqlite/libsqlite/src/pragma.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/pragma.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/pragma.c -o ext/sqlite/libsqlite/src/pragma.lo 
ext/sqlite/libsqlite/src/vacuum.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/vacuum.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/vacuum.c -o ext/sqlite/libsqlite/src/vacuum.lo 
ext/sqlite/libsqlite/src/copy.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/copy.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/copy.c -o ext/sqlite/libsqlite/src/copy.lo 
ext/sqlite/libsqlite/src/vdbeaux.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/vdbeaux.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/vdbeaux.c -o ext/sqlite/libsqlite/src/vdbeaux.lo 
ext/sqlite/libsqlite/src/date.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/date.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/date.c -o ext/sqlite/libsqlite/src/date.lo 
ext/sqlite/libsqlite/src/where.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/where.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/where.c -o ext/sqlite/libsqlite/src/where.lo 
ext/sqlite/libsqlite/src/trigger.lo: /root/php-5.3.8/ext/sqlite/libsqlite/src/trigger.c
	$(LIBTOOL) --mode=compile $(CC) -I/root/php-5.3.8/ext/sqlite/libsqlite/src -Iext/sqlite/libsqlite/src -I/root/php-5.3.8/ext -Iext/sqlite/ -I/root/php-5.3.8/ext/sqlite/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/sqlite/libsqlite/src/trigger.c -o ext/sqlite/libsqlite/src/trigger.lo 
ext/standard/crypt_freesec.lo: /root/php-5.3.8/ext/standard/crypt_freesec.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/crypt_freesec.c -o ext/standard/crypt_freesec.lo 
ext/standard/crypt_blowfish.lo: /root/php-5.3.8/ext/standard/crypt_blowfish.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/crypt_blowfish.c -o ext/standard/crypt_blowfish.lo 
ext/standard/crypt_sha512.lo: /root/php-5.3.8/ext/standard/crypt_sha512.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/crypt_sha512.c -o ext/standard/crypt_sha512.lo 
ext/standard/crypt_sha256.lo: /root/php-5.3.8/ext/standard/crypt_sha256.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/crypt_sha256.c -o ext/standard/crypt_sha256.lo 
ext/standard/php_crypt_r.lo: /root/php-5.3.8/ext/standard/php_crypt_r.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/php_crypt_r.c -o ext/standard/php_crypt_r.lo 
ext/standard/array.lo: /root/php-5.3.8/ext/standard/array.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/array.c -o ext/standard/array.lo 
ext/standard/base64.lo: /root/php-5.3.8/ext/standard/base64.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/base64.c -o ext/standard/base64.lo 
ext/standard/basic_functions.lo: /root/php-5.3.8/ext/standard/basic_functions.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/basic_functions.c -o ext/standard/basic_functions.lo 
ext/standard/browscap.lo: /root/php-5.3.8/ext/standard/browscap.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/browscap.c -o ext/standard/browscap.lo 
ext/standard/crc32.lo: /root/php-5.3.8/ext/standard/crc32.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/crc32.c -o ext/standard/crc32.lo 
ext/standard/crypt.lo: /root/php-5.3.8/ext/standard/crypt.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/crypt.c -o ext/standard/crypt.lo 
ext/standard/cyr_convert.lo: /root/php-5.3.8/ext/standard/cyr_convert.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/cyr_convert.c -o ext/standard/cyr_convert.lo 
ext/standard/datetime.lo: /root/php-5.3.8/ext/standard/datetime.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/datetime.c -o ext/standard/datetime.lo 
ext/standard/dir.lo: /root/php-5.3.8/ext/standard/dir.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/dir.c -o ext/standard/dir.lo 
ext/standard/dl.lo: /root/php-5.3.8/ext/standard/dl.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/dl.c -o ext/standard/dl.lo 
ext/standard/dns.lo: /root/php-5.3.8/ext/standard/dns.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/dns.c -o ext/standard/dns.lo 
ext/standard/exec.lo: /root/php-5.3.8/ext/standard/exec.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/exec.c -o ext/standard/exec.lo 
ext/standard/file.lo: /root/php-5.3.8/ext/standard/file.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/file.c -o ext/standard/file.lo 
ext/standard/filestat.lo: /root/php-5.3.8/ext/standard/filestat.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/filestat.c -o ext/standard/filestat.lo 
ext/standard/flock_compat.lo: /root/php-5.3.8/ext/standard/flock_compat.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/flock_compat.c -o ext/standard/flock_compat.lo 
ext/standard/formatted_print.lo: /root/php-5.3.8/ext/standard/formatted_print.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/formatted_print.c -o ext/standard/formatted_print.lo 
ext/standard/fsock.lo: /root/php-5.3.8/ext/standard/fsock.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/fsock.c -o ext/standard/fsock.lo 
ext/standard/head.lo: /root/php-5.3.8/ext/standard/head.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/head.c -o ext/standard/head.lo 
ext/standard/html.lo: /root/php-5.3.8/ext/standard/html.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/html.c -o ext/standard/html.lo 
ext/standard/image.lo: /root/php-5.3.8/ext/standard/image.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/image.c -o ext/standard/image.lo 
ext/standard/info.lo: /root/php-5.3.8/ext/standard/info.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/info.c -o ext/standard/info.lo 
ext/standard/iptc.lo: /root/php-5.3.8/ext/standard/iptc.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/iptc.c -o ext/standard/iptc.lo 
ext/standard/lcg.lo: /root/php-5.3.8/ext/standard/lcg.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/lcg.c -o ext/standard/lcg.lo 
ext/standard/link.lo: /root/php-5.3.8/ext/standard/link.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/link.c -o ext/standard/link.lo 
ext/standard/mail.lo: /root/php-5.3.8/ext/standard/mail.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/mail.c -o ext/standard/mail.lo 
ext/standard/math.lo: /root/php-5.3.8/ext/standard/math.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/math.c -o ext/standard/math.lo 
ext/standard/md5.lo: /root/php-5.3.8/ext/standard/md5.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/md5.c -o ext/standard/md5.lo 
ext/standard/metaphone.lo: /root/php-5.3.8/ext/standard/metaphone.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/metaphone.c -o ext/standard/metaphone.lo 
ext/standard/microtime.lo: /root/php-5.3.8/ext/standard/microtime.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/microtime.c -o ext/standard/microtime.lo 
ext/standard/pack.lo: /root/php-5.3.8/ext/standard/pack.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/pack.c -o ext/standard/pack.lo 
ext/standard/pageinfo.lo: /root/php-5.3.8/ext/standard/pageinfo.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/pageinfo.c -o ext/standard/pageinfo.lo 
ext/standard/quot_print.lo: /root/php-5.3.8/ext/standard/quot_print.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/quot_print.c -o ext/standard/quot_print.lo 
ext/standard/rand.lo: /root/php-5.3.8/ext/standard/rand.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/rand.c -o ext/standard/rand.lo 
ext/standard/soundex.lo: /root/php-5.3.8/ext/standard/soundex.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/soundex.c -o ext/standard/soundex.lo 
ext/standard/string.lo: /root/php-5.3.8/ext/standard/string.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/string.c -o ext/standard/string.lo 
ext/standard/scanf.lo: /root/php-5.3.8/ext/standard/scanf.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/scanf.c -o ext/standard/scanf.lo 
ext/standard/syslog.lo: /root/php-5.3.8/ext/standard/syslog.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/syslog.c -o ext/standard/syslog.lo 
ext/standard/type.lo: /root/php-5.3.8/ext/standard/type.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/type.c -o ext/standard/type.lo 
ext/standard/uniqid.lo: /root/php-5.3.8/ext/standard/uniqid.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/uniqid.c -o ext/standard/uniqid.lo 
ext/standard/url.lo: /root/php-5.3.8/ext/standard/url.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/url.c -o ext/standard/url.lo 
ext/standard/var.lo: /root/php-5.3.8/ext/standard/var.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/var.c -o ext/standard/var.lo 
ext/standard/versioning.lo: /root/php-5.3.8/ext/standard/versioning.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/versioning.c -o ext/standard/versioning.lo 
ext/standard/assert.lo: /root/php-5.3.8/ext/standard/assert.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/assert.c -o ext/standard/assert.lo 
ext/standard/strnatcmp.lo: /root/php-5.3.8/ext/standard/strnatcmp.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/strnatcmp.c -o ext/standard/strnatcmp.lo 
ext/standard/levenshtein.lo: /root/php-5.3.8/ext/standard/levenshtein.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/levenshtein.c -o ext/standard/levenshtein.lo 
ext/standard/incomplete_class.lo: /root/php-5.3.8/ext/standard/incomplete_class.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/incomplete_class.c -o ext/standard/incomplete_class.lo 
ext/standard/url_scanner_ex.lo: /root/php-5.3.8/ext/standard/url_scanner_ex.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/url_scanner_ex.c -o ext/standard/url_scanner_ex.lo 
ext/standard/ftp_fopen_wrapper.lo: /root/php-5.3.8/ext/standard/ftp_fopen_wrapper.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/ftp_fopen_wrapper.c -o ext/standard/ftp_fopen_wrapper.lo 
ext/standard/http_fopen_wrapper.lo: /root/php-5.3.8/ext/standard/http_fopen_wrapper.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/http_fopen_wrapper.c -o ext/standard/http_fopen_wrapper.lo 
ext/standard/php_fopen_wrapper.lo: /root/php-5.3.8/ext/standard/php_fopen_wrapper.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/php_fopen_wrapper.c -o ext/standard/php_fopen_wrapper.lo 
ext/standard/credits.lo: /root/php-5.3.8/ext/standard/credits.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/credits.c -o ext/standard/credits.lo 
ext/standard/css.lo: /root/php-5.3.8/ext/standard/css.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/css.c -o ext/standard/css.lo 
ext/standard/var_unserializer.lo: /root/php-5.3.8/ext/standard/var_unserializer.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/var_unserializer.c -o ext/standard/var_unserializer.lo 
ext/standard/ftok.lo: /root/php-5.3.8/ext/standard/ftok.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/ftok.c -o ext/standard/ftok.lo 
ext/standard/sha1.lo: /root/php-5.3.8/ext/standard/sha1.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/sha1.c -o ext/standard/sha1.lo 
ext/standard/user_filters.lo: /root/php-5.3.8/ext/standard/user_filters.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/user_filters.c -o ext/standard/user_filters.lo 
ext/standard/uuencode.lo: /root/php-5.3.8/ext/standard/uuencode.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/uuencode.c -o ext/standard/uuencode.lo 
ext/standard/filters.lo: /root/php-5.3.8/ext/standard/filters.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/filters.c -o ext/standard/filters.lo 
ext/standard/proc_open.lo: /root/php-5.3.8/ext/standard/proc_open.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/proc_open.c -o ext/standard/proc_open.lo 
ext/standard/streamsfuncs.lo: /root/php-5.3.8/ext/standard/streamsfuncs.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/streamsfuncs.c -o ext/standard/streamsfuncs.lo 
ext/standard/http.lo: /root/php-5.3.8/ext/standard/http.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/standard/ -I/root/php-5.3.8/ext/standard/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/standard/http.c -o ext/standard/http.lo 
ext/tokenizer/tokenizer.lo: /root/php-5.3.8/ext/tokenizer/tokenizer.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/tokenizer/ -I/root/php-5.3.8/ext/tokenizer/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/tokenizer/tokenizer.c -o ext/tokenizer/tokenizer.lo 
ext/tokenizer/tokenizer_data.lo: /root/php-5.3.8/ext/tokenizer/tokenizer_data.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/tokenizer/ -I/root/php-5.3.8/ext/tokenizer/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/tokenizer/tokenizer_data.c -o ext/tokenizer/tokenizer_data.lo 
ext/xml/xml.lo: /root/php-5.3.8/ext/xml/xml.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/xml/ -I/root/php-5.3.8/ext/xml/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/xml/xml.c -o ext/xml/xml.lo 
ext/xml/compat.lo: /root/php-5.3.8/ext/xml/compat.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/xml/ -I/root/php-5.3.8/ext/xml/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/xml/compat.c -o ext/xml/compat.lo 
ext/xmlreader/php_xmlreader.lo: /root/php-5.3.8/ext/xmlreader/php_xmlreader.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/xmlreader/ -I/root/php-5.3.8/ext/xmlreader/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/xmlreader/php_xmlreader.c -o ext/xmlreader/php_xmlreader.lo 
ext/xmlwriter/php_xmlwriter.lo: /root/php-5.3.8/ext/xmlwriter/php_xmlwriter.c
	$(LIBTOOL) --mode=compile $(CC)  -Iext/xmlwriter/ -I/root/php-5.3.8/ext/xmlwriter/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/ext/xmlwriter/php_xmlwriter.c -o ext/xmlwriter/php_xmlwriter.lo 
TSRM/TSRM.lo: /root/php-5.3.8/TSRM/TSRM.c
	$(LIBTOOL) --mode=compile $(CC)  -ITSRM/ -I/root/php-5.3.8/TSRM/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/TSRM/TSRM.c -o TSRM/TSRM.lo 
TSRM/tsrm_strtok_r.lo: /root/php-5.3.8/TSRM/tsrm_strtok_r.c
	$(LIBTOOL) --mode=compile $(CC)  -ITSRM/ -I/root/php-5.3.8/TSRM/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/TSRM/tsrm_strtok_r.c -o TSRM/tsrm_strtok_r.lo 
TSRM/tsrm_virtual_cwd.lo: /root/php-5.3.8/TSRM/tsrm_virtual_cwd.c
	$(LIBTOOL) --mode=compile $(CC)  -ITSRM/ -I/root/php-5.3.8/TSRM/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/TSRM/tsrm_virtual_cwd.c -o TSRM/tsrm_virtual_cwd.lo 
main/main.lo: /root/php-5.3.8/main/main.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/main.c -o main/main.lo 
main/snprintf.lo: /root/php-5.3.8/main/snprintf.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/snprintf.c -o main/snprintf.lo 
main/spprintf.lo: /root/php-5.3.8/main/spprintf.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/spprintf.c -o main/spprintf.lo 
main/php_sprintf.lo: /root/php-5.3.8/main/php_sprintf.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_sprintf.c -o main/php_sprintf.lo 
main/safe_mode.lo: /root/php-5.3.8/main/safe_mode.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/safe_mode.c -o main/safe_mode.lo 
main/fopen_wrappers.lo: /root/php-5.3.8/main/fopen_wrappers.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/fopen_wrappers.c -o main/fopen_wrappers.lo 
main/alloca.lo: /root/php-5.3.8/main/alloca.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/alloca.c -o main/alloca.lo 
main/php_scandir.lo: /root/php-5.3.8/main/php_scandir.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_scandir.c -o main/php_scandir.lo 
main/php_ini.lo: /root/php-5.3.8/main/php_ini.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_ini.c -o main/php_ini.lo 
main/SAPI.lo: /root/php-5.3.8/main/SAPI.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/SAPI.c -o main/SAPI.lo 
main/rfc1867.lo: /root/php-5.3.8/main/rfc1867.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/rfc1867.c -o main/rfc1867.lo 
main/php_content_types.lo: /root/php-5.3.8/main/php_content_types.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_content_types.c -o main/php_content_types.lo 
main/strlcpy.lo: /root/php-5.3.8/main/strlcpy.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/strlcpy.c -o main/strlcpy.lo 
main/strlcat.lo: /root/php-5.3.8/main/strlcat.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/strlcat.c -o main/strlcat.lo 
main/mergesort.lo: /root/php-5.3.8/main/mergesort.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/mergesort.c -o main/mergesort.lo 
main/reentrancy.lo: /root/php-5.3.8/main/reentrancy.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/reentrancy.c -o main/reentrancy.lo 
main/php_variables.lo: /root/php-5.3.8/main/php_variables.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_variables.c -o main/php_variables.lo 
main/php_ticks.lo: /root/php-5.3.8/main/php_ticks.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_ticks.c -o main/php_ticks.lo 
main/network.lo: /root/php-5.3.8/main/network.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/network.c -o main/network.lo 
main/php_open_temporary_file.lo: /root/php-5.3.8/main/php_open_temporary_file.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_open_temporary_file.c -o main/php_open_temporary_file.lo 
main/php_logos.lo: /root/php-5.3.8/main/php_logos.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/php_logos.c -o main/php_logos.lo 
main/output.lo: /root/php-5.3.8/main/output.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/output.c -o main/output.lo 
main/getopt.lo: /root/php-5.3.8/main/getopt.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/getopt.c -o main/getopt.lo 
main/streams/streams.lo: /root/php-5.3.8/main/streams/streams.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/streams.c -o main/streams/streams.lo 
main/streams/cast.lo: /root/php-5.3.8/main/streams/cast.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/cast.c -o main/streams/cast.lo 
main/streams/memory.lo: /root/php-5.3.8/main/streams/memory.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/memory.c -o main/streams/memory.lo 
main/streams/filter.lo: /root/php-5.3.8/main/streams/filter.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/filter.c -o main/streams/filter.lo 
main/streams/plain_wrapper.lo: /root/php-5.3.8/main/streams/plain_wrapper.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/plain_wrapper.c -o main/streams/plain_wrapper.lo 
main/streams/userspace.lo: /root/php-5.3.8/main/streams/userspace.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/userspace.c -o main/streams/userspace.lo 
main/streams/transports.lo: /root/php-5.3.8/main/streams/transports.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/transports.c -o main/streams/transports.lo 
main/streams/xp_socket.lo: /root/php-5.3.8/main/streams/xp_socket.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/xp_socket.c -o main/streams/xp_socket.lo 
main/streams/mmap.lo: /root/php-5.3.8/main/streams/mmap.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/mmap.c -o main/streams/mmap.lo 
main/streams/glob_wrapper.lo: /root/php-5.3.8/main/streams/glob_wrapper.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/streams/ -I/root/php-5.3.8/main/streams/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/main/streams/glob_wrapper.c -o main/streams/glob_wrapper.lo 
main/internal_functions.lo: main/internal_functions.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c main/internal_functions.c -o main/internal_functions.lo 
main/internal_functions_cli.lo: main/internal_functions_cli.c
	$(LIBTOOL) --mode=compile $(CC)  -Imain/ -I/root/php-5.3.8/main/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c main/internal_functions_cli.c -o main/internal_functions_cli.lo 
Zend/zend_language_parser.lo: /root/php-5.3.8/Zend/zend_language_parser.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_language_parser.c -o Zend/zend_language_parser.lo 
Zend/zend_language_scanner.lo: /root/php-5.3.8/Zend/zend_language_scanner.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_language_scanner.c -o Zend/zend_language_scanner.lo 
Zend/zend_ini_parser.lo: /root/php-5.3.8/Zend/zend_ini_parser.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_ini_parser.c -o Zend/zend_ini_parser.lo 
Zend/zend_ini_scanner.lo: /root/php-5.3.8/Zend/zend_ini_scanner.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_ini_scanner.c -o Zend/zend_ini_scanner.lo 
Zend/zend_alloc.lo: /root/php-5.3.8/Zend/zend_alloc.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_alloc.c -o Zend/zend_alloc.lo 
Zend/zend_compile.lo: /root/php-5.3.8/Zend/zend_compile.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_compile.c -o Zend/zend_compile.lo 
Zend/zend_constants.lo: /root/php-5.3.8/Zend/zend_constants.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_constants.c -o Zend/zend_constants.lo 
Zend/zend_dynamic_array.lo: /root/php-5.3.8/Zend/zend_dynamic_array.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_dynamic_array.c -o Zend/zend_dynamic_array.lo 
Zend/zend_execute_API.lo: /root/php-5.3.8/Zend/zend_execute_API.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_execute_API.c -o Zend/zend_execute_API.lo 
Zend/zend_highlight.lo: /root/php-5.3.8/Zend/zend_highlight.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_highlight.c -o Zend/zend_highlight.lo 
Zend/zend_llist.lo: /root/php-5.3.8/Zend/zend_llist.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_llist.c -o Zend/zend_llist.lo 
Zend/zend_opcode.lo: /root/php-5.3.8/Zend/zend_opcode.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_opcode.c -o Zend/zend_opcode.lo 
Zend/zend_operators.lo: /root/php-5.3.8/Zend/zend_operators.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_operators.c -o Zend/zend_operators.lo 
Zend/zend_ptr_stack.lo: /root/php-5.3.8/Zend/zend_ptr_stack.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_ptr_stack.c -o Zend/zend_ptr_stack.lo 
Zend/zend_stack.lo: /root/php-5.3.8/Zend/zend_stack.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_stack.c -o Zend/zend_stack.lo 
Zend/zend_variables.lo: /root/php-5.3.8/Zend/zend_variables.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_variables.c -o Zend/zend_variables.lo 
Zend/zend.lo: /root/php-5.3.8/Zend/zend.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend.c -o Zend/zend.lo 
Zend/zend_API.lo: /root/php-5.3.8/Zend/zend_API.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_API.c -o Zend/zend_API.lo 
Zend/zend_extensions.lo: /root/php-5.3.8/Zend/zend_extensions.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_extensions.c -o Zend/zend_extensions.lo 
Zend/zend_hash.lo: /root/php-5.3.8/Zend/zend_hash.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_hash.c -o Zend/zend_hash.lo 
Zend/zend_list.lo: /root/php-5.3.8/Zend/zend_list.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_list.c -o Zend/zend_list.lo 
Zend/zend_indent.lo: /root/php-5.3.8/Zend/zend_indent.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_indent.c -o Zend/zend_indent.lo 
Zend/zend_builtin_functions.lo: /root/php-5.3.8/Zend/zend_builtin_functions.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_builtin_functions.c -o Zend/zend_builtin_functions.lo 
Zend/zend_sprintf.lo: /root/php-5.3.8/Zend/zend_sprintf.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_sprintf.c -o Zend/zend_sprintf.lo 
Zend/zend_ini.lo: /root/php-5.3.8/Zend/zend_ini.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_ini.c -o Zend/zend_ini.lo 
Zend/zend_qsort.lo: /root/php-5.3.8/Zend/zend_qsort.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_qsort.c -o Zend/zend_qsort.lo 
Zend/zend_multibyte.lo: /root/php-5.3.8/Zend/zend_multibyte.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_multibyte.c -o Zend/zend_multibyte.lo 
Zend/zend_ts_hash.lo: /root/php-5.3.8/Zend/zend_ts_hash.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_ts_hash.c -o Zend/zend_ts_hash.lo 
Zend/zend_stream.lo: /root/php-5.3.8/Zend/zend_stream.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_stream.c -o Zend/zend_stream.lo 
Zend/zend_iterators.lo: /root/php-5.3.8/Zend/zend_iterators.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_iterators.c -o Zend/zend_iterators.lo 
Zend/zend_interfaces.lo: /root/php-5.3.8/Zend/zend_interfaces.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_interfaces.c -o Zend/zend_interfaces.lo 
Zend/zend_exceptions.lo: /root/php-5.3.8/Zend/zend_exceptions.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_exceptions.c -o Zend/zend_exceptions.lo 
Zend/zend_strtod.lo: /root/php-5.3.8/Zend/zend_strtod.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_strtod.c -o Zend/zend_strtod.lo 
Zend/zend_gc.lo: /root/php-5.3.8/Zend/zend_gc.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_gc.c -o Zend/zend_gc.lo 
Zend/zend_closures.lo: /root/php-5.3.8/Zend/zend_closures.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_closures.c -o Zend/zend_closures.lo 
Zend/zend_float.lo: /root/php-5.3.8/Zend/zend_float.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_float.c -o Zend/zend_float.lo 
Zend/zend_objects.lo: /root/php-5.3.8/Zend/zend_objects.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_objects.c -o Zend/zend_objects.lo 
Zend/zend_object_handlers.lo: /root/php-5.3.8/Zend/zend_object_handlers.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_object_handlers.c -o Zend/zend_object_handlers.lo 
Zend/zend_objects_API.lo: /root/php-5.3.8/Zend/zend_objects_API.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_objects_API.c -o Zend/zend_objects_API.lo 
Zend/zend_default_classes.lo: /root/php-5.3.8/Zend/zend_default_classes.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_default_classes.c -o Zend/zend_default_classes.lo 
Zend/zend_execute.lo: /root/php-5.3.8/Zend/zend_execute.c
	$(LIBTOOL) --mode=compile $(CC)  -IZend/ -I/root/php-5.3.8/Zend/ $(COMMON_FLAGS) $(CFLAGS_CLEAN) $(EXTRA_CFLAGS)  -c /root/php-5.3.8/Zend/zend_execute.c -o Zend/zend_execute.lo 
