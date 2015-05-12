# Copyright (c) 2015 SUSE LLC. All Rights Reserved.
# Author: Stefan Koch <skoch@suse.de>
# 
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2 of the GNU General
# Public License as published by the Free Software Foundation.
# 
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program; if not, contact SUSE LLC.
# 
# To contact SUSE about this file by physical or electronic mail,
# you may find current contact information at www.suse.com

Name: usbauth
Version: 1.0
Release: 0
Group: System/Security
License: GPL-2.0
Summary: USB firewall against BadUSB attacks
Url: https://build.opensuse.org/package/show/home:skoch_suse/usbauth

BuildRoot: %{tmppath}/%{name}-build
Source0: %{name}.tar.bz2
Source1: %{name}-rpmlintrc

#Requires: libusbauth_configparser
#Requires: libudev1
#Requires: libdbus-1-3
#Requires: dbus-1
Requires: udev
Requires: systemd
BuildRequires: libusbauth_configparser-devel
BuildRequires: libudev-devel
BuildRequires: dbus-1-devel
BuildRequires: pkg-config

%description
It is a firewall against BadUSB attacks. A config file descibes in which way devices would be accepted.

%prep
%setup -n %{name}

%build
make -C Release

%install
mkdir -p %{buildroot}%_sbindir/
mkdir -p %{buildroot}%_sysconfdir/dbus-1/system.d/
mkdir -p %{buildroot}/usr/lib/udev/rules.d/
mkdir -p %{buildroot}%_mandir/man1/
cp Release/usbauth %{buildroot}%_sbindir
cp data/usbauth.conf %{buildroot}%_sysconfdir/usbauth.conf
cp data/dbus.conf %{buildroot}%_sysconfdir/dbus-1/system.d/org.opensuse.usbauth.conf
cp data/20-usbauth.rules %{buildroot}/usr/lib/udev/rules.d/
gzip -c data/usbauth.1 > %{buildroot}%_mandir/man1/usbauth.1.gz

%files
%defattr(-,root,root)
%_sbindir/usbauth
%config %_sysconfdir/usbauth.conf
%config %_sysconfdir/dbus-1/system.d/org.opensuse.usbauth.conf
/usr/lib/udev/rules.d/20-usbauth.rules

%doc COPYING README
%doc %_mandir/man1/usbauth.1.gz

%post
%{?udev_rules_update:%udev_rules_update}

%postun
%{?udev_rules_update:%udev_rules_update}

%changelog
* Tue May 5 2015 skoch@suse.de
- initial created spec file

