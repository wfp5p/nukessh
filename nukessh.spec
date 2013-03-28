Summary: Nuke ssh brute force attempts
Name: nukessh
Version: 0.9
Release: 2%{?dist}
License: WTFPL
Source0: nukessh-%{version}.tar.gz
Group: System Environment/Base
BuildArchitectures: noarch

BuildRequires:  perl(ExtUtils::MakeMaker)
Requires: perl(DBD::SQLite)

%if 0%{?rhel}
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/chkconfig
Requires(preun): /sbin/service
Requires(postun): /sbin/service
%else
Requires(post): systemd-units
Requires(preun): systemd-units
Requires(postun): systemd-units
BuildRequires: systemd-units
%endif


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


mkdir -p $RPM_BUILD_ROOT/usr/sbin/

install -m 555 nukessh.pl  $RPM_BUILD_ROOT/usr/sbin/nukessh

%if 0%{?rhel}
mkdir -p $RPM_BUILD_ROOT/etc/init.d
install -m 544 nukessh.init $RPM_BUILD_ROOT/etc/init.d/nukessh
%else
install -d -m755 $RPM_BUILD_ROOT/%{_unitdir}
install -m644 nukessh.service $RPM_BUILD_ROOT/%{_unitdir}/nukessh.service
install -d $RPM_BUILD_ROOT/etc/sysconfig/
install -m644 nukessh.sysconfig $RPM_BUILD_ROOT/etc/sysconfig/nukessh
%endif

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

%if 0%{?rhel}
/etc/init.d/nukessh
%else
%config(noreplace) %{_sysconfdir}/sysconfig/nukessh
%attr(0644,root,root) %{_unitdir}/nukessh.service
%endif

%post

mkdir -p /var/cache/nukessh
mkdir -p /var/log/nukessh

%if 0%{?rhel}
chkconfig --add nukessh
chkconfig nukessh on
%else
/bin/systemctl enable nukessh.service >/dev/null 2>&1 || :
%endif

%preun
if [ $1 = 0 ]; then
%if 0%{?rhel}
   /sbin/service nukessh stop
   /sbin/chkconfig --del nukessh
%else
    /bin/systemctl --no-reload disable nukessh.service > /dev/null 2>&1 || :
    /bin/systemctl stop nukessh.service >/dev/null 2>&1 || :
%endif
fi


%changelog
* Tue Aug 21 2012 Bill Pemberton <wfp5p@virginia.edu> - 0.9-1
- Make RHEL and Fedora version


