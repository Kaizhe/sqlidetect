#! /bin/bash

set -eux

function isRunning() {
	local name="$1"
	local running=$(docker ps --format='{{.Names}}' --filter "name=$1")
	if [ -z "$running" ]; then
		echo "$1 is not running";
		return 0;
	else
		echo "$1 is running";
		return 1;
	fi;
}

function isInit() {
	local serverStatus=0;
	local clientStatus=0;
	local attackerStatus=0;

	isRunning "mysql-client"
	if [ $? -eq 1 ]; then
		clientStatus=1;
	fi;

	isRunning "mysql-attacker"
	if [ $? -eq 1 ]; then
		attackerStatus=1;
	fi;

	isRunning "mysql-server"
	if [ $? -eq 1 ]; then
		serverStatus=1;
	fi;

	if [ $clientStatus -eq 1 -a $serverStatus -eq 1 -a $attackerStatus -eq 1 ]; then
		return 0;
	else
		return 1;
	fi;
}

function init() {
	docker rm -f mysql-server mysql-client mysql-attacker || true

	server=$(docker run --label "com.docker.compose.service=mysql-server" --label "app=MySQL-Server" --name mysql-server -e MYSQL_ROOT_PASSWORD=welcome -d kaizheh/mysql:latest)
	client=$(docker run --label "com.docker.compose.service=mysql-client" --label "app=MySQL-Client" --name mysql-client -e MYSQL_ROOT_PASSWORD=welcome -d kaizheh/mysql:latest)	
	attacker=$(docker run --label "com.docker.compose.service=mysql-attacker" --label "app=MySQL-Attacker" --name mysql-attacker -e MYSQL_ROOT_PASSWORD=welcome -d kaizheh/mysql:latest)	
	server_ip=$(docker inspect $server --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
	client_ip=$(docker inspect $client --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
	attacker_ip=$(docker inspect $attacker --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

	echo "MySQL server IP: $server_ip"
	echo "MySQL client IP: $client_ip"
	echo "MySQL attacker IP: $attacker_ip"
	sleep 45
        docker exec mysql-client bash -c "mysql -uroot -pwelcome -h $server_ip --ssl-mode=disabled -f < /init.sql"
}

function action() {
	local action="$1";
	local num="$2";
	local sql_file=""
	local client=""

	if ! isInit ; then
		init
	fi;
	
	if [ -z "$num" ]; then
		num=1;
	fi;

	if [ "$action" = "daily" ]; then
		sql_file="daily.sql"
		client="mysql-client"
	elif [ "$action" = "mal" ]; then
		sql_file="mal.sql";
		client="mysql-attacker"
	else
		echo "invalid activity"
		exit 1;
	fi;	

	server_ip=$(docker inspect mysql-server --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')

	echo "repeated: $num"
	for (( c=0; c<$num; c++ ))
	do
        	docker exec $client  bash -c "mysql -uroot -pwelcome -h $server_ip --ssl-mode=disabled -f < /$sql_file"
	done
}

function daily_sql() {
	action "daily" $1
}

function mal_act_sql() {
	action "mal" $1
}

if [ $# -eq 0 ]; then
	echo "valid input parameter: init, daily, malact-sql, malact-mining"
	exit 1;
fi

opt="$1";
counts=300

if [ "$opt" == "init" ]; then
	init
elif [ "$opt" == "daily" ]; then
	daily_sql $counts
elif [ "$opt" == "malact-sql" ]; then
	mal_act_sql 1
elif [ "$opt" == "all" ]; then
	init
	daily $counts
	mal_act_sql 1
else
	echo "valid input parameter: all, init, daily, malact-sql"
	exit 1;
fi;

exit 0;
