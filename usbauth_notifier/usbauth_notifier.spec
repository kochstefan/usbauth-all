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

Name: usbauth_notifier
Version: 1.0
Release: 0
Group: System/X11/Utilities
License: GPL-2.0
Summary: Notifier for USB Firewall to use with desktop environments
Url: https://build.opensuse.org/package/show/home:skoch_suse/usbauth_notifier

BuildRoot: %{tmppath}/%{name}-build
Source0: %{name}.tar.bz2

#Requires: libusbauth_configparser
#Requires: libudev1
#Requires: libdbus-1-3
#Requires: libnotify4
#Requires: libglib-2_0-0
#Requires: libgobject-2_0-0
#Requires: udev
#Requires: dbus-1
Requires: xinit
BuildRequires: libusbauth_configparser-devel
BuildRequires: libudev-devel
BuildRequires: dbus-1-devel
BuildRequires: libnotify-devel
BuildRequires: glib2-devel
BuildRequires: pkg-config
BuildRequires: gettext-runtime

%description
A notifier for the usbauth firewall against BadUSB attacks. The user could manually allow or deny USB devices.

%prep
%setup -n %{name}

%build
make -C Release
make -C Release_npriv

%install
mkdir -p %{buildroot}%_bindir/
mkdir -p %{buildroot}%_sysconfdir/X11/xinit/xinitrc.d/
mkdir -p %{buildroot}%_mandir/man1/
mkdir -p %{buildroot}%_datadir/locale/de/LC_MESSAGES/
cp Release/usbauth_notifier %{buildroot}%_bindir
cp Release_npriv/usbauth_npriv %{buildroot}%_bindir
cp data/usbauth_notifier.sh %{buildroot}%_sysconfdir/X11/xinit/xinitrc.d/
msgfmt data/de.po -o %{buildroot}/usr/share/locale/de/LC_MESSAGES/usbauth_notifier.mo
gzip -c data/usbauth_notifier.1 > %{buildroot}%_mandir/man1/usbauth_notifier.1.gz
gzip -c data/usbauth_npriv.1 > %{buildroot}%_mandir/man1/usbauth_npriv.1.gz

%files
%defattr(-,root,root)
%_bindir/usbauth_notifier
%_bindir/usbauth_npriv
%_sysconfdir/X11/xinit/
%_sysconfdir/X11/xinit/xinitrc.d/
%_sysconfdir/X11/xinit/xinitrc.d/usbauth_notifier.sh
%_datadir/locale/de/LC_MESSAGES/usbauth_notifier.mo

%doc COPYING README
%doc %_mandir/man1/usbauth_notifier.1.gz
%doc %_mandir/man1/usbauth_npriv.1.gz

%post
chmod +s %_bindir/usbauth_npriv

%changelog
* Tue May 5 2015 skoch@suse.de
- initial created spec file
