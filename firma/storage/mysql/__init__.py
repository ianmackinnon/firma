# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import re
import sys
import getpass
import logging

from pathlib import Path
from hashlib import sha1

import pymysql
from sqlalchemy import event



LOG = logging.getLogger('mysql')



MYSQL_ERROR = {
    "DB_NO_EXIST_DROP": 1008,
    "ACCESS_DENIED_CREDS": 1045,
    "DB_NO_EXIST": 1049,
    "USER_NO_EXIST_DROP": 1396,
    "ACCESS_DENIED_CONFIG": 1698,
    "CONNECTION_FAILED": 2003,
}



def verify_mysql_name(key):
    fail = None
    value = os.environ[key]
    if not re.match("[0-9A-Za-z_]*$", value):
        fail = True
        LOG.error("`%s` may only contain digits, ASCII letters and underscores.", key)
    if len(value) > 16:
        fail = True
        LOG.error("`%s` may be a maximum of 16 characters.", key)
    if fail:
        LOG.error("Anything else can cause problems for some versions of MySQL.")
        sys.exit(1)



def verify_mysql_user(account: str):
    verify_mysql_name(user_name(account))
    verify_mysql_name(user_pass(account))



def split(text):
    values = []
    parts = re.split(r"( on [^,]+),\s*", text, flags=re.I) + [""]

    for i in range(0, len(parts), 2):
        value = "".join(parts[i:i + 2])
        values.append(value)

    return values



def user_name(account):
    return f"DB_USER_{account}_NAME"



def user_pass(account):
    return f"DB_USER_{account}_PASS"



def user_privs(account):
    return f"DB_USER_{account}_PRIVS"



def user_host(account):
    return f"DB_USER_{account}_HOST"



def env_accounts():
    is_set = {
        "NAME": set(),
        "PASS": set(),
        "PRIVS": set(),
        "HOST": set(),
    }
    for k in os.environ:
        if match := re.match(r"DB_USER_([A-Z]{2,8})_(NAME|PASS|PRIVS|HOST)$", k):
            account, item = match.groups()
            is_set[item].add(account)

    if (
            not (is_set["NAME"] == is_set["PASS"] == is_set["PRIVS"])
            or (is_set["HOST"] - is_set["NAME"])
    ):
        LOG.error(".env DB user variables do not fully match:")
        for k in is_set:
            LOG.error("DB_USER_..._%s:  %s", k, ", ".join(is_set[k]))
        sys.exit(1)

    if not is_set["NAME"]:
        LOG.error("No .env DB user variables are defined.")
        sys.exit(1)

    return list(is_set["NAME"])



def connection_url(
        username: str,
        password: str,
        database: str,
        host: str | None = None,
        port: int | None = None,
):
    login = f"{username}:{password}@"

    if host is None:
        host = "localhost"
    if host == "localhost":
        host = "127.0.0.1"  # Prevents MySQL from using a socket
    if port is not None:
        host += ":{port}"

    path = f"/{database}?charset=utf8"

    return f"mysql+pymysql://{login}{host}{path}"



def mysql_connection_url(
        account: str,
):
    """
    Create connection URL from environment variables and account name.
    """

    return connection_url(
        os.environ[user_name(account)],
        os.environ[user_pass(account)],
        os.environ["DB_NAME"],
        host=os.environ.get("DB_HOST", None),
        port=os.environ.get("DB_PORT", None),
    )



def engine_sql_mode(engine, sql_mode=""):
    def set_sql_mode(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"SET sql_mode = '{sql_mode}'")
    event.listen(engine, "first_connect", set_sql_mode, insert=True)
    event.listen(engine, "connect", set_sql_mode)



def engine_disable_mode(engine, mode):
    def set_sql_mode(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"SET sql_mode=(SELECT REPLACE(@@sql_mode,'{mode}',''))")
    event.listen(engine, "first_connect", set_sql_mode, insert=True)
    event.listen(engine, "connect", set_sql_mode)



def engine_set_optimizer_switch(engine, key, value):
    value_text = "on" if value else "off"
    def set_optimizer_switch(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(f"SET optimizer_switch='{key}={value_text}';")
    event.listen(engine, "first_connect", set_optimizer_switch, insert=True)
    event.listen(engine, "connect", set_optimizer_switch)



def drop_user(
        cursor,
        username: str,
        host: str | None = None,
):
    if host is None:
        host = "localhost"
    try:
        cursor.execute(f"drop user '{username}'@'{host}';")
        LOG.debug(f"User `{username}` dropped.")
    except pymysql.err.OperationalError as e:
        if e.args[0] == MYSQL_ERROR["USER_NO_EXIST_DROP"]:
            LOG.debug(f"User `{username}` did not exist.")
        else:
            raise e


def create_user(
        cursor,
        username: str,
        password: str,
        privs: list,
        host: str | None = None,
):
    if host is None:
        host = "localhost"
    drop_user(cursor, username)
    user_full = f"'{username}'@'{host}'"
    cmd = f"create user {user_full} identified by '{password}';"
    LOG.debug(cmd)
    cursor.execute(cmd)
    for priv in privs:
        cmd = f"grant {priv}.* to {user_full};"
        LOG.debug(cmd)
        cursor.execute(cmd)
    LOG.debug(f"User `{username}` created with permissions.")




def mysql_drop_users(cursor, accounts):
    for account in accounts:
        host = os.environ.get(user_host(account), None)

        drop_user(cursor, os.environ[user_name(account)], host=host)



def mysql_drop_database(cursor, name):
    try:
        cursor.execute("drop database %s;" % name)
        LOG.debug("Databse %s dropped.", name)
    except pymysql.err.OperationalError as e:
        if e.args[0] == MYSQL_ERROR["DB_NO_EXIST_DROP"]:
            LOG.debug("Database %s did not exist.", name)
        else:
            raise e



def mysql_create_users(
        cursor,
        accounts,
):
    for account in accounts:
        privs = []

        priv_str = os.environ.get(user_privs(account), None)
        if priv_str:
            priv_values = {k: v for k, v in os.environ.items() if k.endswith("DB_NAME")}
            privs += split(priv_str.format(**priv_values))

        host = os.environ.get(user_host(account), None)

        create_user(cursor, os.environ[user_name(account)], os.environ[user_pass(account)], privs, host=host)



# Database utility functions



def database_hash(
        account: str,
):
    db_options = {
        "user": os.environ[user_name(account)],
        "passwd": os.environ[user_pass(account)],
        "database": os.environ["DB_NAME"],
        "host": os.environ.get("DB_HOST", "localhost"),
    }
    if port := os.environ.get("DB_PORT", None):
        db_options["port"] = port

    sys.stdout.flush()

    try:
        connection = pymysql.connect(**db_options)
    except pymysql.err.OperationalError as e:
        LOG.error("Could not connect with supplied credentials.")
        raise e
    cursor = connection.cursor()

    hasher = sha1()
    cursor.execute("show tables;")
    result = cursor.fetchall()
    for (table, ) in result:
        cursor.execute("checksum table %s extended;" % table)
        result2 = cursor.fetchone()
        if not result2:
            break
        (_table_path, checksum, ) = result2

        hasher.update(("%s=%s;" % (table, checksum)).encode())

    return hasher.hexdigest()



# Database configuration file functions



def mysql_generate_conf(
        account: str,
        dump: bool = False
):
    if dump:
        sys.stdout.write( \
"""[client]
user=%s
password=%s
""" % (
    os.environ[user_name(account)],
    os.environ[user_pass(account)],
))
    else:
        sys.stdout.write( \
"""[client]
database=%s
user=%s
password=%s
""" % (
    os.environ["DB_NAME"],
    os.environ[user_name(account)],
    os.environ[user_pass(account)],
))



def get_cursor(db_options):
    try:
        connection = pymysql.connect(**db_options)
    except pymysql.err.OperationalError as e:
        if e.args[0] == MYSQL_ERROR["ACCESS_DENIED_CREDS"]:
            if "using password: NO" in str(e):
                LOG.error("Could not access database. No password was supplied.")
                sys.exit(1)
            elif "using password: YES" in str(e):
                LOG.error("Could not access database.")
                LOG.error("-   Supplied password may be incorrect.")
                LOG.error("-   User password may not have been initialized.")
                LOG.error("-   MySql Root account may be disabled for non-root OS users.")
                sys.exit(1)
        if e.args[0] == MYSQL_ERROR["ACCESS_DENIED_CONFIG"]:
            # Access denied
            # This is the error that occurs if we try to initialize the database
            # when MaríaDB has been installed but not setup yet.
            LOG.error("Could not access database.")
            LOG.error("-   Supplied password may be incorrect.")
            LOG.error("-   User password may not have been initialized.")
            if "root" in str(e):
                LOG.error("-   MySql Root account may be disabled for non-root OS users.")
            sys.exit(1)
        if e.args[0] == MYSQL_ERROR["CONNECTION_FAILED"]:
            # Cannot connect
            LOG.error("Could not connect to MySQL server at localhost.")
            LOG.error("-   Check the server is running. `ps -ef | grep mysql`.")
            LOG.error("-   If `/var/run/mysqld/mysqld.sock` exists, the server is.")
            LOG.error("    running, but not accepting connections to localhost.")
            sys.exit(1)
        else:
            LOG.error("Could not connect with supplied credentials.")
        raise e

    cursor = connection.cursor()

    return cursor



def get_root_cursor():
    return get_cursor({
        "host": "localhost",
        "user": "root",
        "passwd": getpass.getpass("MySQL root password: "),
    })



def get_account_cursor(account):
    return get_cursor({
        "host": "localhost",
        "user": os.environ[user_name(account)],
        "passwd": os.environ[user_pass(account)],
        # "unix_socket": "/var/run/mysqld/mysqld.sock",
    })



def mysql_create(
        accounts: list
):
    if mysql_test(accounts):
        LOG.info("Database and users already correctly set up. Nothing to do.")
        return

    cursor = get_root_cursor()

    try:
        cursor.execute(f"use {os.environ['DB_NAME']};")
    except pymysql.err.OperationalError as e:
        if e.args[0] == MYSQL_ERROR["DB_NO_EXIST"]:
            LOG.debug(f"Database {os.environ['DB_NAME']} does not exist.")

            cursor.execute(f"""create database {os.environ['DB_NAME']}
DEFAULT CHARACTER SET = utf8
DEFAULT COLLATE = utf8_bin;""")

            cursor.execute(f"use {os.environ['DB_NAME']};")
        else:
            raise e


    LOG.debug(f"Database {os.environ['DB_NAME']} exists.")

    mysql_create_users(cursor, accounts)



def mysql_test(
        accounts: list
):
    """Returns True if successful, False if unsuccessful."""

    status = True

    assert accounts

    database = os.environ['DB_NAME']

    for account in accounts:
        username = os.environ[user_name(account)]
        message = f"database `{database}` as `{account}` user `{username}`."
        try:
            pymysql.connect(
                host="localhost",
                user=os.environ[user_name(account)],
                passwd=os.environ[user_pass(account)],
                db=os.environ["DB_NAME"],
            )
        except pymysql.err.OperationalError:
            status = False
            LOG.debug(f"Could not connect to {message}.")
        else:
            LOG.debug("Successfully connected to {message}.")

    return status



def drop_database_tables(cursor, database):
    # This requires the `metadata-lock-info-plugin`:
    # https://mariadb.com/kb/en/metadata-lock-info-plugin/
    cursor.execute("select table_name, user, host from information_schema.metadata_lock_info join information_schema.processlist on (id) where lock_type = 'Table metadata lock' and table_schema = '%s';" % database)
    rows = list(cursor.fetchall())
    if rows:
        LOG.error("The following tables are locked and cannot be dropped:")
        LOG.error("")
        LOG.error("  %-16s | %-16s | %-16s", "Table", "User", "Host")
        LOG.error("  %-16s | %-16s | %-16s", *(["-" * 16] * 3))
        for row in rows:
            LOG.error("  %-16s | %-16s | %-16s", *row)
        LOG.error("")
        sys.exit(1)

    cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
    while True:
        cursor.execute("show full tables where table_type = 'VIEW';")
        result = cursor.fetchone()
        if not result:
            break
        (name, _type) = result
        cursor.execute("drop view %s;" % name)
        LOG.debug("Dropped view %s.", name)
    while True:
        cursor.execute("show full tables where table_type = 'BASE TABLE';")
        result = cursor.fetchone()
        if not result:
            break
        (name, _type) = result
        cursor.execute("drop table %s;" % name)
        LOG.debug("Dropped table %s.", name)
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")



def drop_database_triggers(cursor, database):
    LOG.warning("DROP ALL TRIGGERS")
    cursor.execute("""select trigger_name
from information_schema.triggers
where trigger_schema = '%s';""", database)
    result = cursor.fetchall()
    for (trigger, ) in result:
        cursor.execute("drop trigger %s;" % trigger)
        LOG.debug("Dropped trigger %s.", trigger)



def mysql_empty(cursor):
    drop_database_tables(cursor, os.environ["DB_NAME"])



def mysql_drop_triggers(cursor):
    drop_database_triggers(cursor, os.environ["DB_NAME"])



def mysql_source(cursor, source):
    cursor.execute(Path(source).read_text("utf-8"))
