
%define is_mandrake %(test -e /etc/mandrake-release && echo 1 || echo 0)
%define is_suse %(test -e /etc/SuSE-release && echo 1 || echo 0)
%define is_fedora %(test -e /etc/fedora-release && echo 1 || echo 0)
%define is_centos %(test -e /etc/centos-release && echo 1 || echo 0)

%define dist redhat
%define disttag rh
%define kde_path %{_prefix}

%if %is_mandrake
%define dist mandrake
%define disttag mdk
%endif
%if %is_suse
%define dist suse
%define disttag suse
%define kde_path /opt/kde3
%endif
%if %is_fedora
%define dist fedora
%define disttag rhfc
%endif
%if %is_centos
%define dist centos
%define disttag el
%endif

%define distver %(rpm -q %{dist}-release > /dev/null ; if test $? != 0 ; then ver="`rpm -q --queryformat='%{Version}' %{dist}-userland-release 2> /dev/null | cut -d'.' -f1`" ; else ver="`rpm -q --queryformat='%{Version}' %{dist}-release 2> /dev/null | cut -d'.' -f1`" ; fi ; echo "$ver")
#-%define distlibsuffix %(%{_bindir}/kde-config --libsuffix 2>/dev/null)
%define distlibsuffix %(echo "`rpm --eval %{_lib}`")
%define libdir %{distlibsuffix}

%if %distver == 7
%define __debug_install_post %{_rpmconfigdir}/find-debuginfo.sh %{?_find_debuginfo_opts} "%{_builddir}/%{?buildsubdir}" %{nil}
%endif

%define _bindir		%{kde_path}/bin
%define _datadir	%{kde_path}/share
%define _iconsdir	%{_datadir}/icons
%define _docdir		%{_datadir}/doc
%define _localedir	%{_datadir}/locale

%define	name      libazftp
%define summary   Az FTP Server and Client
%define version   0.1.0
%define release   1.%{disttag}%{distver}
%define license   GPL
%define group     Applications/File
%define source    %{name}-%{version}.tar.gz
%define url       https://github.com/Dynasty-Az/libazftp
%define vendor    Az
%define packager  Az

#-%define	userpath  /libazmemp

Name:		%{name}
Version:	%{version}
Release:	%{release}
Summary:	%{summary}
Group:		%{group}
License:	%{license}
URL:		%{url}
Source0:	%{source}
Prefix:		%{_prefix}
BuildRoot:	%{_tmppath}/%{name}-%{version}-%{release}-root
BuildRequires:  libazctools-devel >= 2.48.0
Requires:       libazctools >= 2.48.0


%description
This is a library for memroy pool and some tools.

%package devel
#Requires:
Summary: %{summary} development files
Group: %{group}
Provides: %{name}-devel
Requires: %{name} == %{version}

%description devel
This package contains necessary header files for %{name} development.
This package is necessary to compile plugins for %{name}.

%prep
echo %{_target}
echo %{_target_alias}
echo %{_target_cpu}
echo %{_target_os}
echo %{_target_vendor}
#echo %{kde_path}
echo %{release}
#echo %{_prefix}
#echo %{_lib}
#echo %{distlibsuffix}
echo Building %{name}-%{version}-%{release}
sleep 5
%setup -n %{name}-%{version}


%build
./configure --prefix=%{_prefix} --libdir=%{_prefix}/%{_lib}
make

%install
echo $RPM_BUILD_ROOT
make DESTDIR=$RPM_BUILD_ROOT install

%files
%defattr(-,root,root,-)
#%attr(0755,root,root)
%{_bindir}/azftpd
%{_bindir}/azftpcli
%dir %{kde_path}/%{_lib}/%{name}/
%{kde_path}/%{_lib}/%{name}/*.so
%{kde_path}/%{_lib}/%{name}/*.so.*
/etc/*
/etc/.*

%files devel
%dir %{kde_path}/include/azftp/
%{kde_path}/include/azftp/*.h
%{kde_path}/%{_lib}/%{name}/*.la
%{kde_path}/%{_lib}/%{name}/*.a

%doc

%clean
[ ${RPM_BUILD_ROOT} != "/" ] && rm -rf ${RPM_BUILD_ROOT}
rm -rf $RPM_BUILD_DIR/%{name}-%{version}

%pre
rm -f /etc/ld.so.conf.d/libazftp.conf

%post
touch /etc/ld.so.conf.d/libazftp.conf
echo %{_prefix}/%{_lib}/%{name}/ >> /etc/ld.so.conf.d/libazftp.conf
#echo "/usr/local/lib/libazctools/">>/etc/ld.so.conf.d/libazctools.conf
#echo "/usr/local/lib64/libazctools/">>/etc/ld.so.conf.d/libazctools.conf
#echo "/usr/lib/libazctools/">>/etc/ld.so.conf.d/libazctools.conf
#echo "/usr/lib64/libazctools/">>/etc/ld.so.conf.d/libazctools.conf
ldconfig

%preun

%postun
if (( $1 == 0 ))
then
    rm -f /etc/ld.so.conf.d/libazftp.conf
fi

%postun devel

%changelog
