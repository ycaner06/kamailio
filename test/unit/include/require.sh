# Copyright (C) 2017 Mikko Lehto
# Copyright (C) 2008 1&1 Internet AG
#
# This file is part of kamailio, a free SIP server.
#
# kamailio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version
#
# kamailio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

. include/common

check_kamailio() {
	if ! (test -e $BIN) ; then
		echo "kamailio not found, not run"
		return 1
	fi;
	return 0
}

check_module() {
	if [ $# -ne 1 ]; then
		echo "wrong number of params in check_module()"
		return 1
	fi

	if ! (test -e $SRC_DIR/modules/$1/$1.so) ; then
		echo "$SRC_DIR/modules/$1/$1.so not found, not run"
		return 1
	fi;
	return 0
}

check_netcat() {
	if ! ( which nc > /dev/null ); then
		echo "netcat not found, not run"
		return 1
	fi;
	return 0
}

check_sipp() {
	if ! ( which sipp > /dev/null ); then
		echo "sipp not found, not run"
		return 1
	fi;
	return 0
}

check_sipsak() {
	if ! ( which sipsak > /dev/null ); then
		echo "sipsak not found, not run"
		return 1
	fi;
	return 0
}

