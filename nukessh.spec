Summary: nuke ssh brute force attempts
Name: nukessh
Version: 0.2
Release: 1
License: distributable
Source0: nukessh-%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-root
Group: System Environment/Base
Autoreqprov: false
BuildArchitectures: noarch

Requires: perl(File::Tail)
Requires: perl(Log::Dispatch)
Requires: perl(GDBM_File)
Requires: perl(AppConfig)

%description
Daemon to detect and block ssh brute force attempts

%prep
%setup

%build
%install

rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/var/cache/nukessh
mkdir -p $RPM_BUILD_ROOT/var/log/nukessh
mkdir -p $RPM_BUILD_ROOT/usr/sbin/

install -m 555 nukessh.pl  $RPM_BUILD_ROOT/usr/sbin/nukessh
install -m 544 nukessh $RPM_BUILD_ROOT/etc/init.d/nukessh

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
/usr/sbin/nukessh
/etc/init.d/nukessh
/var/cache/nukessh
/var/log/nukessh

%post

chkconfig --add nukessh
chkconfig nukessh on

%preun

/sbin/service nukessh stop

%postun

