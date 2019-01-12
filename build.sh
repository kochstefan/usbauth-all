#!/bin/bash

# Copyright (C) 2017-2019 Stefan Koch <stefan.koch10@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of version 2.1 of the GNU Lesser General
# Public License as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.

type="$1"
vsuffix="-1.0"

if [ -z "$type" ]; then
	echo "Usage:"
	echo "build.sh rpm"
	echo "build.sh deb"
	echo "build.sh am"
	echo "build.sh obs home:repo"
	exit
fi

for pkg in libusbauth-configparser usbauth usbauth-notifier; do
	if [ -d $pkg ]; then

		if [ $type = rpm ] || [ $type = obs ]; then
			tar cvfj ${pkg}${vsuffix}.tar.bz2 $pkg
		fi

		pushd $pkg
		if [ $type = rpm ]; then
			./autogen.sh
			./configure
		elif [ $type = deb ]; then
			ln -s ../packages/$pkg/debian
			dpkg-buildpackage -us -uc
			rm debian
		elif [ $type = am ]; then
			./autogen.sh
		fi
		popd

		if [ $type = rpm ]; then
			mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
			mv ${pkg}${vsuffix}.tar.bz2 ~/rpmbuild/SOURCES
			cp -f $pkg/$pkg-rpmlintrc ~/rpmbuild/SOURCES
			cp $pkg/$pkg.spec ~/rpmbuild/SPECS
			/usr/lib/build/changelog2spec $pkg/$pkg.changelog >> ~/rpmbuild/SPECS/$pkg.spec
			rpmbuild -ba ~/rpmbuild/SPECS/$pkg.spec
		elif [ $type = obs ]; then
			osc checkout "$2"
			osc meta pkg -e "$2" $pkg
			osc up "$2"
			mv ${pkg}${vsuffix}.tar.bz2 "$2"/$pkg/
			pushd $pkg
			./autogen.sh
			./configure
			cp $pkg.spec ../"$2"/$pkg/
			cp $pkg.changes ../"$2"/$pkg/
			popd
			osc add "$2"/$pkg/*
			osc commit "$2"
		fi
	fi
done
