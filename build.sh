#!/bin/bash

# Copyright (C) 2017 Stefan Koch <stefan.koch10@gmail.com>
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

if [ -z "$type" ]; then
	echo "Usage:"
	echo "build.sh rpm"
	echo "build.sh deb"
	echo "build.sh am"
	echo "build.sh obs home:repo"
	exit
fi

for pkg in *; do
	if [ -d $pkg ]; then
		pushd $pkg
		if [ $type = rpm ]; then
			./autogen.sh
			./configure
		elif [ $type = deb ]; then
			dpkg-buildpackage -us -uc
		elif [ $type = am ]; then
			./autogen.sh
		fi
		popd

		if [ $type = rpm ]; then
			tar cvfj $pkg.tar.bz2 $pkg
			mkdir -p ~/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}
			mv $pkg.tar.bz2 ~/rpmbuild/SOURCES
			cp -f $pkg/$pkg-rpmlintrc ~/rpmbuild/SOURCES
			cp $pkg/$pkg.spec ~/rpmbuild/SPECS
			rpmbuild -ba ~/rpmbuild/SPECS/$pkg.spec
		elif [ $type = obs ]; then
			osc checkout "$2"
			osc meta pkg -e "$2" $pkg
			osc up "$2"
			tar cvfj $pkg.tar.bz2 $pkg
			mv $pkg.tar.bz2 "$2"/$pkg/
			pushd $pkg
			./autogen.sh
			./configure
			cp $pkg.spec ../"$2"/$pkg/
			cp -f $pkg-rpmlintrc ../"$2"/$pkg/
			popd
			osc add "$2"/$pkg/*
			osc commit "$2"
		fi
	fi
done
