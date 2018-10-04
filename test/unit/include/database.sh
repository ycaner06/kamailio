# Copyright (C) 2017 mslehto@iki.fi
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
KAMUSER="kamailio"
MYSQL="mysql kamailio --show-warnings --batch --user="${KAMUSER}" --password=kamailiorw -e"

export PGPASSWORD="kamailiorw"
PSQL="psql -A -t -n -q -h localhost -U kamailio kamailio -c"

ISQL="isql -b -v -d0x0 kamailio kamailio kamailiorw"

check_mysql() {
	$MYSQL "select * from location;" > /dev/null
	if ! [ "$?" -eq 0 ] ; then
		echo "can't read from database"
		return 1
	fi;
	$MYSQL "insert into location (user_agent) values ('___test___');" > /dev/null
	if ! [ "$?" -eq 0 ] ; then
		echo "can't write to database"
		return 1
	fi;
	$MYSQL "delete from location where user_agent ='___test___';" > /dev/null
	return 0
}

check_postgres() {
	$PSQL "select * from location;" > /dev/null
	if ! [ "$?" -eq 0 ] ; then
		echo "can't read from database"
		return 1
	fi;
	$PSQL "insert into location (user_agent) values ('___test___');" > /dev/null
	if ! [ "$?" -eq 0 ] ; then
		echo "can't write to database"
		return 1
	fi;
	$PSQL "delete from location where user_agent ='___test___';" > /dev/null
	return 0
}

check_unixodbc() {
	echo "select * from location;" | $ISQL  > /dev/null
	if ! [ "$?" -eq 0 ] ; then
		echo "can't read from database"
		return 1
	fi;
	echo "insert into location (id, user_agent) values ('$RANDOM', '___test___');" | $ISQL > /dev/null
	if ! [ "$?" -eq 0 ] ; then
		echo "can't write to database"
		return 1
	fi;
	echo "delete from location where user_agent ='___test___';" | $ISQL > /dev/null
	return 0
}
