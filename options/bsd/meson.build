if not bsd_option
	subdir_done()
endif

libc_sources += files(
	'generic/arpa-nameser.cpp',
	'generic/ether.cpp',
	'generic/getopt.cpp',
	'generic/bsd_stdlib.cpp',
	'generic/pty.cpp',
)

if not no_headers
	install_headers(
		'include/fstab.h',
		'include/pty.h',
		'include/utmp.h',
	)
	# nameser.h and telnet.h are now installed by posix/meson.build
	install_headers(
		'include/arpa/nameser_compat.h',
		subdir: 'arpa'
	)
	install_headers(
		'include/sys/queue.h',
		subdir: 'sys'
	)
	install_headers(
		'include/netinet/ether.h',
		subdir: 'netinet'
	)
	install_headers(
		'include/bits/bsd/bsd_stdlib.h',
		subdir: 'bits/bsd'
	)
endif
