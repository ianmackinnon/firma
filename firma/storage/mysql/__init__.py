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

import re
import os
import sys
import getpass
import logging
import configparser
from hashlib import sha1
from collections import namedtuple

import pymysql
from sqlalchemy import event



LOG = logging.getLogger('mysql')

Options = namedtuple(
    "Options",
    [
        "database",
        "app_username",
        "app_password",
        "app_privileges",
        "admin_username",
        "admin_password",
        "admin_privileges",
    ]
)



def verify(string, section, name):
    if not re.match("[0-9A-Za-z_]*$", string):
        LOG.error("Error: '%s' is invalid.", string)
        LOG.error(
            "%s:%s should only contain digits, ASCII letters and underscores.",
            section, name)
        LOG.error(
            "Anything else can cause problems for some versions of MySQL.")
        sys.exit(1)
    if len(string) > 16:
        LOG.error(
            "Error: %s:%s may be a maximum of 16 characters.", section, name)
        LOG.error(
            "Anything else can cause problems for some versions of MySQL.")
        sys.exit(1)



def split(text):
    values = []
    for value in text.split(","):
        value = value.strip()
        if value:
            values.append(value)
    return values



def load_conf(path):
    # pylint: disable=protected-access
    # Storing config path in protected variable

    if not os.path.isfile(path):
        LOG.error("%s: File not found", path)
        sys.exit(1)
    config = configparser.ConfigParser()
    config.read(path)
    config._load_path = path
    return config



def get_conf(path):
    config = load_conf(path)

    names = load_database_names(config)

    database = names["default"]

    try:
        app_username = config.get("mysql-app", "username")
        app_password = config.get("mysql-app", "password")
        app_privileges = config["mysql-app"].get("privileges", None)
        if app_privileges:
            app_privileges = replace_database_names(names, app_privileges)
            app_privileges = split(app_privileges)
        else:
            app_privileges = []
    except:
        app_username = None
        app_password = None
        app_privileges = None
    else:
        verify(app_username, "mysql-app", "username")
        verify(app_password, "mysql-app", "password")

    admin_username = config.get("mysql-admin", "username")
    admin_password = config.get("mysql-admin", "password")
    admin_privileges = config["mysql-admin"].get("privileges", None)
    if admin_privileges:
        admin_privileges = replace_database_names(names, admin_privileges)
        admin_privileges = split(admin_privileges)
    else:
        admin_privileges = []

    verify(database, "mysql", "default")
    verify(admin_username, "mysql-admin", "username")
    verify(admin_password, "mysql-admin", "password")

    options = Options(
        database,
        app_username,
        app_password,
        app_privileges,
        admin_username,
        admin_password,
        admin_privileges,
    )

    return options



def replace_database_names(names, text):
    """
    Accepts either a "format" style string with database names
    in curly braces, or a solitary database name.
    """
    if re.compile(r"^[a-z-]+$").match(text):
        text = "{%s}" % text
    return text.format(**names)



def load_database_names(conf):
    """
    Accepts string or config instance.
    """
    # pylint: disable=protected-access
    # Storing file path in config object.

    if isinstance(conf, str):
        config = load_conf(conf)
    else:
        assert isinstance(conf, configparser.ConfigParser)
        config = conf

    names = {}
    for key in config["mysql"]:
        if key == "default":
            continue
        names[key] = config.get("mysql", key)

    default = config["mysql"].get("default")
    if default:
        names["default"] = replace_database_names(names, default)

    return names



def mysql_connection_url(username, password, database,
                         host=None, port=None):
    login = "%s:%s@" % (username, password)

    if host is None:
        host = "localhost"
    if host == "localhost":
        host = "127.0.0.1"  # Prevents MySQL from using a socket
    if port is not None:
        host += ":%d" % port

    path = "/%s?charset=utf8" % database

    return "mysql+pymysql://%s%s%s" % (login, host, path)



def connection_url_admin(conf_path, host=None, port=None):
    options = get_conf(conf_path)
    return mysql_connection_url(
        options.admin_username, options.admin_password, options.database,
        host=host, port=port)



def connection_url_app(conf_path, host=None, port=None):
    options = get_conf(conf_path)
    return mysql_connection_url(
        options.app_username, options.app_password, options.database,
        host=host, port=port)



def engine_sql_mode(engine, sql_mode=""):
    def set_sql_mode(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("SET sql_mode = '%s'" % sql_mode)
    event.listen(engine, "first_connect", set_sql_mode, insert=True)
    event.listen(engine, "connect", set_sql_mode)


def engine_disable_mode(engine, mode):
    def set_sql_mode(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute(
            "SET sql_mode=(SELECT REPLACE(@@sql_mode,'%s',''))" % mode)
    event.listen(engine, "first_connect", set_sql_mode, insert=True)
    event.listen(engine, "connect", set_sql_mode)



def drop_user(cursor, username):
    try:
        cursor.execute("drop user '%s'@'localhost';" % username)
        LOG.debug("User %s dropped.", username)
    except pymysql.err.InternalError as e:
        if e.args[0] != 1396:
            raise e
        LOG.debug("User %s did not exist.", username)



def create_user(cursor, username, password, privileges):
    drop_user(cursor, username)
    user = "'%s'@'localhost'" % username
    cursor.execute("create user %s identified by '%s';" % (user, password))
    for privilege in privileges:
        cursor.execute("grant %s.* to %s;" % (privilege, user))
    LOG.debug("User %s created with permissions.", username)



def drop_database(cursor, name):
    try:
        cursor.execute("drop database %s;" % name)
        LOG.debug("Databse %s dropped.", name)
    except pymysql.err.InternalError as e:
        if e.args[0] != 1008:
            raise e
        LOG.debug("Database %s did not exist.", name)



def mysql_drop(cursor, options):
    drop_user(cursor, options.admin_username)
    drop_user(cursor, options.app_username)
    drop_database(cursor, options.database)



def mysql_update_users(cursor, options):
    if options.app_username:
        create_user(cursor, options.app_username, options.app_password, [
            "select, insert, update, delete on %s" % options.database,
        ] + options.app_privileges)

    create_user(cursor, options.admin_username, options.admin_password, [
        "all privileges on %s" % options.database,
        # "reload on %s" % options.database,
    ] + options.admin_privileges)


# Checksum

def database_hash(conf_path):
    options = get_conf(conf_path)

    db_options = {
        "host": "localhost",
        "user": options.app_username,
        "passwd": options.app_password,
        "database": options.database,
    }

    try:
        connection = pymysql.connect(**db_options)
    except pymysql.err.InternalError as e:
        LOG.error("Could not connect with supplied credentials.")
        print(e)
        sys.exit(1)
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



# Configuration



def mysql_generate_conf(options, account=None, dump=False):
    if account is None:
        account = "admin"
    assert account in ("admin", "app")

    if dump:
        sys.stdout.write( \
"""[client]
user=%s
password=%s
""" % (
    getattr(options, account + "_username"),
    getattr(options, account + "_password")
))
    else:
        sys.stdout.write( \
"""[client]
database=%s
user=%s
password=%s
""" % (
    options.database,
    getattr(options, account + "_username"),
    getattr(options, account + "_password")
))



def get_cursor(db_options):
    try:
        connection = pymysql.connect(**db_options)
    except pymysql.err.OperationalError as e:
        if str(e).startswith("(1045,"):
            # Access denied
            if "using password: NO" in str(e):
                LOG.error("Could not access database. No password was supplied.")
                sys.exit(1)
            elif "using password: YES" in str(e):
                LOG.error("Could not access database.")
                LOG.error("-   Supplied password may be incorrect.")
                LOG.error("-   User password may not have been initialized.")
                LOG.error("-   MySql Root account may be disabled for non-root OS users.")
                sys.exit(1)
        if str(e).startswith("(1698,"):
            # Access denied
            # This is the error that occurs if we try to initialize the database
            # when MaríaDB has been installed but not setup yet.
            LOG.error("Could not access database.")
            LOG.error("-   Supplied password may be incorrect.")
            LOG.error("-   User password may not have been initialized.")
            if "root" in str(e):
                LOG.error("-   MySql Root account may be disabled for non-root OS users.")
            sys.exit(1)
        if str(e).startswith("(2003,"):
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



def get_admin_cursor(options):
    return get_cursor({
        "host": "localhost",
        "user": options.admin_username,
        "passwd": options.admin_password,
        # "unix_socket": "/var/run/mysqld/mysqld.sock",
    })



def mysql_create(options):
    if mysql_test(options):
        LOG.info("Database and users already correctly set up. Nothing to do.")
        return

    cursor = get_root_cursor()

    try:
        cursor.execute("use %s;" % options.database)
    except pymysql.err.InternalError as e:
        if e.args[0] != 1049:
            raise e

        LOG.debug("Database %s does not exist.", options.database)

        cursor.execute("""create database %s
DEFAULT CHARACTER SET = utf8
DEFAULT COLLATE = utf8_bin;""" % options.database)

        cursor.execute("use %s;" % options.database)

    LOG.debug("Database %s exists.", options.database)

    if options.app_username:
        create_user(cursor, options.app_username, options.app_password, [
            "select, insert, update, delete on %s" % options.database,
        ] + options.app_privileges)

    create_user(cursor, options.admin_username, options.admin_password, [
        "all privileges on %s" % options.database,
        # "reload on %s" % options.database,
    ] + options.admin_privileges)



def mysql_test(options):
    """Returns True if successful, False if unsuccessful."""
    status = True

    assert options.app_username or options.admin_username

    if options.app_username:
        try:
            pymysql.connect(
                host="localhost",
                user=options.app_username,
                passwd=options.app_password,
                db=options.database,
            )
        except pymysql.err.OperationalError:
            status = False
            LOG.debug("Could not connect as app user.")

    if options.admin_username:
        try:
            pymysql.connect(
                host="localhost",
                user=options.admin_username,
                passwd=options.admin_password,
                db=options.database,
            )
        except pymysql.err.OperationalError:
            status = False
            LOG.debug("Could not connect as admin user.")

    return status



def drop_database_tables(cursor):
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
    drop_database_tables(cursor)



def mysql_drop_triggers(cursor, options):
    drop_database_triggers(cursor, options.database)



def mysql_source(cursor, source):
    sql = open(source).read()
    cursor.execute(sql)
