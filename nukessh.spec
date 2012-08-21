Summary: Nuke ssh brute force attempts
Name: nukessh
Version: 0.9
Release: 1
License: GPLv2+ or Artistic
Source0: nukessh-%{version}.tar.gz
Group: System Environment/Base
BuildArchitectures: noarch

BuildRequires:  perl(ExtUtils::MakeMaker)

# Requires: perl(Log::Log4perl)
# Requires: perl(DBI)
# Requires: perl(DBD::SQLite)
# Requires: perl(App::Daemon)
# Requires: perl(AppConfig)
# Requires: perl(IPTables::ChainMgr)
# Requires: perl(POE)

%description
Daemon to detect and block ssh brute force attempts

%prep
%setup -q

%build
cd pm
%{__perl} Makefile.PL INSTALLDIRS=vendor
make

%install

rm -rf $RPM_BUILD_ROOT

mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/usr/sbin/

install -m 555 nukessh.pl  $RPM_BUILD_ROOT/usr/sbin/nukessh
install -m 544 nukessh.init $RPM_BUILD_ROOT/etc/init.d/nukessh

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
if [ $1 = 0 ]; then
   /sbin/service nukessh stop
   /sbin/chkconfig --del nukessh
fi


%changelog

* Thu Apr  7 2011 Bill Pemberton <wfp5p@virginia.edu> - 0.8-1
- Something
