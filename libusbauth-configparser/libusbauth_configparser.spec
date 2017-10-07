# Copyright (c) 2015 SUSE LLC. All Rights Reserved.
# Author: Stefan Koch <skoch@suse.de>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, contact SUSE LLC.
#
# To contact SUSE about this file by physical or electronic mail,
# you may find current contact information at www.suse.com

Name: libusbauth_configparser
Version: 0.8
Release: 0
Group: System/Libraries
License: LGPL-2.1
Summary: Library for USB Firewall including flex/bison parser
Url: https://build.opensuse.org/package/show/home:skoch_suse/libusbauth_configparser

BuildRoot: %{tmppath}/%{name}-build
Source0: %{name}.tar.bz2

#Requires: libudev1
BuildRequires: libudev-devel
BuildRequires: bison
BuildRequires: flex
BuildRequires: pkg-config

%description
Library to read usbauth config file into data structures

%package -n %{name}0
Group: System/Libraries
License: LGPL-2.1
Summary: Library for USB Firewall including flex/bison parser

%package devel
Group: Development/Libraries
License: LGPL-2.1
Summary: Development part of library for USB Firewall including flex/bison parser
Requires: libusbauth_configparser0 = %{version}

%description -n %{name}0
Library to read usbauth config file into data structures

%description devel
Development part of library to read usbauth config file into data structures

%prep
%setup -n %{name}

%build
make -C Release

%install
mkdir -p %{buildroot}%{_libdir}/
mkdir -p %{buildroot}%{_includedir}/usbauth/
mkdir -p %{buildroot}%_mandir/man3/
mkdir -p %{buildroot}%{_libdir}/pkgconfig/
cp Release/libusbauth_configparser.so %{buildroot}%{_libdir}/libusbauth_configparser.so.0.0
ln -s %{_libdir}/libusbauth_configparser.so.0.0 %{buildroot}%{_libdir}/libusbauth_configparser.so.0
cp src/generic.h %{buildroot}%{_includedir}/usbauth/
cp src/usbauth_configparser.h %{buildroot}%{_includedir}/usbauth/
gzip -c data/libusbauth_configparser.3 > %{buildroot}%_mandir/man3/libusbauth_configparser.3.gz
cp data/libusbauth_configparser.pc %{buildroot}%{_libdir}/pkgconfig/
ln -s %{_libdir}/libusbauth_configparser.so.0.0 %{buildroot}%{_libdir}/libusbauth_configparser.so

%files -n %{name}0
%defattr(-,root,root)
%_libdir/libusbauth_configparser.so.0.0
%_libdir/libusbauth_configparser.so.0

%doc COPYING README

%files devel
%defattr(-,root,root)
%_includedir/usbauth/
%_includedir/usbauth/generic.h
%_includedir/usbauth/usbauth_configparser.h
%_libdir/libusbauth_configparser.so
%_libdir/pkgconfig/
%_libdir/pkgconfig/libusbauth_configparser.pc

%doc COPYING README
%doc %_mandir/man3/libusbauth_configparser.3.gz

%post -n %{name}0
%{run_ldconfig}

%postun -n %{name}0
%{run_ldconfig}

%changelog
* Tue May 5 2015 skoch@suse.de
- initial created spec file

