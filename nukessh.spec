Summary: nuke ssh brute force attempts
Name: nukessh
Version: 0.8
Release: 1
License: distributable
Source0: nukessh-%{version}.tar.gz
Buildroot: %{_tmppath}/%{name}-%{version}-root
Group: System Environment/Base
Autoreqprov: false
BuildArchitectures: noarch

Requires: perl(Log::Log4perl)
Requires: perl(DBI)
Requires: perl(DBD::SQLite)
Requires: perl(App::Daemon)
Requires: perl(AppConfig)
Requires: perl(IPTables::ChainMgr)
Requires: perl(POE)

%description
Daemon to detect and block ssh brute force attempts

%prep
%setup

%build
cd pm
%{__perl} Makefile.PL INSTALLDIRS=vendor
make

%install

rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/usr/sbin/

install -m 555 nukessh.pl  $RPM_BUILD_ROOT/usr/sbin/nukessh
install -m 544 nukessh $RPM_BUILD_ROOT/etc/init.d/nukessh

cd pm
make pure_install PERL_INSTALL_ROOT=$RPM_BUILD_ROOT
find $RPM_BUILD_ROOT -type f -name .packlist -exec rm -f {} \;
find $RPM_BUILD_ROOT -depth -type d -exec rmdir {} 2>/dev/null \;

%{_fixperms} $RPM_BUILD_ROOT/*

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%{perl_vendorlib}/*
/usr/sbin/nukessh
/etc/init.d/nukessh

%post

mkdir -p /var/cache/nukessh
mkdir -p /var/log/nukessh

chkconfig --add nukessh
chkconfig nukessh on

%preun

#/sbin/service nukessh stop

%postun

