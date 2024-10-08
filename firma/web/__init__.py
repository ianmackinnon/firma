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
import time
import json
import stat
import errno
import bisect
import base64
import hashlib
import asyncio
import logging
import datetime
import mimetypes
import email.utils
import urllib.parse
from pprint import pformat
from typing import Any, Dict, List
from pathlib import Path
from subprocess import Popen, PIPE
from collections import namedtuple

from dateutil.relativedelta import relativedelta

from onetimepass import valid_totp

import tornado.web
import tornado.auth
import tornado.httpserver
import tornado.options
from tornado import escape
from tornado.log import app_log
from tornado.web import _has_stream_request_body

from sqlalchemy import MetaData, Table, text as sa_text
from sqlalchemy.orm import aliased
from sqlalchemy.exc import DatabaseError
from sqlalchemy.orm.exc import NoResultFound

from firma.util.env import load_env_app



DEFAULTS = {
    "port": 8000,
    "host": "localhost",
}

ARG_DEFAULT = []
PROFILE_PRECISION = 3



Host = namedtuple("Host", ("protocol", "host"))



def defined(options, key, type=None):
    """
    Return the first defined value found in:
    -   Environment variable
    -   Command line options
    -   Defaults
    Undefined values are `None` and `""`.
    """
    env_key = key.upper().replace("-", "_")

    for value in (
            os.environ.get(env_key, None),
            getattr(options, key, None),
            DEFAULTS.get(key, None)
    ):
        if value in (None, ""):
            continue
        if type is not None:
            return type(value)
        return value
    return None



def add_samesite_cookie_support():
    # Not required for Python 3.8+

    from http.cookies import Morsel

    Morsel._reserved[str('samesite')] = str('SameSite')



add_samesite_cookie_support()



class HttpRedirectException(tornado.web.HTTPError):
    """
    Redirect to location, and halt handling.

    `location` may be relative.

    Paths should include calling host URL root if there is one.
    """

    def __init__(self, location, permanent=None):
        status_code = 301 if permanent else 302
        self.location = location
        super().__init__(status_code)



class HttpJsonException(tornado.web.HTTPError):
    def __init__(self, status_code, error_data):
        self.error_data = error_data
        super().__init__(status_code)



class HttpJsonParameterException(HttpJsonException):
    def __init__(self, error_data):
        super().__init__(404, error_data)



class ResourceDependencyException(Exception):
    pass

class ResourceBuildException(Exception):
    pass



class Settings(dict):
    @staticmethod
    def _key(key):
        return re.sub(r"\W|^(?=\d)", "_", key)

    def __getattr__(self, key):
        key = self._key(key)
        value = self.get(key)
        if isinstance(value, dict) and not isinstance(value, Settings):
            self[key] = Settings(value)
            value = self.get(key)
        return value

    def __setattr__(self, key, value):
        key = self._key(key)
        if isinstance(value, dict) and not isinstance(value, Settings):
            value = Settings(value)
        self[key] = value

    def __setitem__(self, key, value):
        key = self._key(key)
        if isinstance(value, dict) and not isinstance(value, Settings):
            value = Settings(value)
        super().__setitem__(key, value)

    def update(self, *args):
        for iter_ in args:
            for key in iter_:
                key = self._key(key)
                if (
                        key in self and
                        isinstance(self[key], dict) and
                        isinstance(iter_[key], dict)
                ):
                    self[key].update(iter_[key])
                else:
                    self[key] = iter_[key]



class Application(tornado.web.Application):
    stats = None

    RESPONSE_LOG_DURATION = 5 * 60  # Seconds
    SESSION_COOKIE_PATH = None

    # Run

    @classmethod
    def run(cls, defaults=None):
        define = tornado.options.define
        options = tornado.options.options

        defaults = dict(DEFAULTS, **(defaults or {}))

        define("host", default=defaults["host"],
               help="Run as the given host")
        define("port", type=int, default=None,
               help="run on the given port")
        define("debug", type=bool, default=None,
               help="Debug mode. Automatic reload.")

        define("mode", default=None,
               help="Include dotenv configuration files matching "
               "`.env.{mode}` and `.env.{mode}.local`")

        define("color", default=None,
               help="Force color format. Options are `ansi`.")

        define("ssl-cert", default=None, help="SSL certificate path")
        define("ssl-key", default=None, help="SSL private key path")

        define("cors", default=None, help="Hosts to allow CORS access "
               "(currently only accepts 'all').")

        define("status", type=bool, default=True,
               help="Enable stats on /server-stats")
        define("label", default=None, help="Label to include in stats")

        define("log-dir", default=None,
               help="Log directory. Write permission required."
               "Logging is disabled if this option is not set.")

        tornado.options.parse_command_line()
        ssl_options = None
        ssl_cert = defined(options, "ssl_cert")
        ssl_key = defined(options, "ssl_cert")
        if ssl_cert and ssl_key:
            ssl_options = {
                "certfile": ssl_cert,
                "keyfile": ssl_key,
            }

        async def main():
            app = cls()
            http_server = tornado.httpserver.HTTPServer(
                app,
                xheaders=True,
                ssl_options=ssl_options,
            )
            http_server.listen(app.settings.port)

            await asyncio.Event().wait()

        asyncio.run(main())


    # Config

    def defined(self, key, type=None):
        return defined(self.settings.options, key, type=type)


    # Stats

    def init_stats(self):
        self.stats = []

    def add_stat(self, key, value):
        self.stats.append((key, value))

    def write_stats(self):
        self.add_stat(
            "Started",
            datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        )

        sys.stdout.write("%s is running.\n" % self.title)
        for key, value in self.stats:
            sys.stdout.write("  %-20s %s\n" % (key + ":", value))
        sys.stdout.flush()


    # Hashing

    @staticmethod
    def sha1_hex(*parts):
        hasher = hashlib.sha1()
        for part in parts:
            hasher.update(part.encode())
        return hasher.hexdigest()


    # Cookies

    @staticmethod
    def load_cookie_secret(path):
        try:
            return path.read_text().strip()
        except IOError:
            sys.stderr.write(
                "could not open xsrf key. run 'make .xsrf' to generate one.\n")
            sys.exit(1)

    def init_cookies(self, prefix, xsrf_path, **kwargs):
        cookie_secret = self.load_cookie_secret(xsrf_path)
        self.settings.update({
            "xsrf_cookies": True,
            "xsrf_cookie_kwargs": {
                "httponly": True,
                "samesite": "strict",
            },
            "cookie_secret": cookie_secret,
        })
        self.settings.app.cookie_prefix = prefix
        self.add_stat("Cookie prefix", prefix)


    # Response Log

    @tornado.gen.coroutine
    def trim_response_log(self):
        start = time.time() - self.RESPONSE_LOG_DURATION
        row = [start, None, None]
        index = bisect.bisect(self.settings.app.response_log, row)
        self.settings.app.response_log = self.settings.app.response_log[index:]

    def init_response_log(self, app):
        app["response_log"] = []
        tornado.ioloop.PeriodicCallback(
            self.trim_response_log,
            self.RESPONSE_LOG_DURATION * 1000
        ).start()


    # Sibling Applications

    def init_sibling(self, db_key, conf_path=None, key=None, value=None):
        if not re.match(r"[a-z_]+$", db_key):
            raise Exception("Sibling name '%s' must consist of lowercase "
                            "letters or underscores" % db_key)

        if not self.settings.app.siblings:
            self.settings.app.siblings = {}

        self.settings.app.siblings[db_key] = {}
        sibling = self.settings.app.siblings[db_key]

        conf_url = None
        if value is not None:
            conf_url = value
        elif conf_path is not None and key is not None:
            conf_url = conf_get(conf_path, 'app', key)
        else:
            raise Exception("Either `value` or `conf_path` and `key` must be supplied.")

        sibling.url = conf_url or None

        self.add_stat(f"URL {db_key}", sibling.url or "offline")


    # URI Log

    def init_log(self, name, log_dir=None, propagate=None, level=None):
        log = self.settings.app.log

        log[name] = {
            "log": logging.getLogger(
                name if name.startswith("tornado")
                else f"{self.name}.{name}"
            )
        }

        if propagate is not None:
            log[name].log.propagate = propagate
        if level is not None:
            log[name].log.setLevel(level)
        if log_dir:
            try:
                os.makedirs(log_dir)
            except OSError as e:
                if e.errno != errno.EEXIST:
                    raise e

            log[name].path = os.path.join(
                log_dir,
                '%s.%s.log' % (self.name, name)
            )

            log[name].log.addHandler(
                logging.handlers.TimedRotatingFileHandler(
                    log[name].path,
                    when="midnight",
                    encoding="utf-8",
                    backupCount=7,
                    utc=True
                )
            )
        else:
            log[name].log.addHandler(logging.NullHandler())

    # Databases

    def mysql_attach_secondary(self, db_key, db_name, query_string):
        if not re.match(r"[a-z_]+$", db_key):
            raise Exception("Database key '%s' must consist of lowercase "
                            "letters or underscores" % db_key)

        if self.settings.app.database is None:
            self.settings.app.database = {}
        db = self.settings.app.database

        db[db_key] = {}
        db[db_key]["database"] = db_name
        db[db_key]["connected"] = False
        db[db_key]["status"] = None

        try:
            self.orm.execute(sa_text(query_string % db_name)).scalar()
            self.mysql_db_success(db_key)
        except DatabaseError as e:
            self.mysql_db_failure(db_key, e)

        self.add_stat(
            "MySQL %s" % db_key,
            "%s (%s)" % (db[db_key]["status"], db_name)
        )

    def mysql_db_success(self, db_key):
        db = self.settings.app.database
        db_name = db[db_key]["database"]
        if not db[db_key]["connected"]:
            app_log.info(
                "Successfully connected to MySQL %s DB '%s'.",
                db_key, db_name)
        db[db_key]["connected"] = True
        db[db_key]["status"] = "Connected"

    def mysql_db_failure(self, db_key, error):
        db = self.settings.app.database
        db_name = db[db_key]["database"]
        if db[db_key].connected:
            app_log.warning(
                "Lost connection to MySQL %s DB '%s'. %s",
                db_key, db_name, str(error))
        elif db[db_key].status is None:
            app_log.warning(
                "Failed to connect to MySQL %s DB '%s'. %s",
                db_key, db_name, str(error))

        db[db_key]["connected"] = False
        if "denied" in str(error):
            db[db_key]["status"] = "Access denied"
        else:
            db[db_key]["status"] = "Cannot connect"

    def mysql_db_name(self, db_key):
        return self.settings.app.database and \
            self.settings.app.database[db_key] and \
            self.settings.app.database[db_key].database

    def mysql_db_connected(self, db_key):
        db = self.settings.app.database
        return db[db_key].get("connected", False)


    # Minify

    def minify_build(self, deps, cwd, static_path, target, debug=None):

        def run(cmd):
            if debug:
                shell_cmd = " ".join([f"'{v}'" for v in cmd])
                app_log.info(shell_cmd)

            proc = Popen(cmd, cwd=cwd, stdout=PIPE, stderr=PIPE)
            (out, err) = proc.communicate()
            out = out.decode("utf-8")
            err = err.decode("utf-8")
            if out:
                app_log.info(out)
            if err:
                app_log.warning(err)
            return proc.returncode


        def build(target):
            """
            Ensure up-to-date target exists
            """

            log_f = app_log.debug

            target_path = static_path / target

            if str(target) not in deps:
                if target_path.exists():
                    log_f("Dependency `%s` exists", target_path)
                else:
                    raise ResourceDependencyException(
                        "Required resource dependency %s does not exist." % target_path)
            else:
                sub_target_mtime = 0
                manifest = deps.get(str(target), None)
                if manifest:
                    for sub_target in manifest["deps"]:
                        build(sub_target)
                        sub_target_mtime = max(
                            sub_target_mtime,
                            (static_path / sub_target).stat().st_mtime
                        )

                if (
                        target_path.exists() and
                        target_path.stat().st_mtime >= sub_target_mtime
                ):
                    log_f("Target `%s` is up to date", target_path)
                else:
                    if target_path.exists():
                        log_f("Target `%s` is out of date", target_path)
                    else:
                        log_f("Target `%s` does not exist", target_path)

                    target_path.parent.mkdir(exist_ok=True)

                    app_log.info("Rebuilding `%s`", target)

                    kwargs = manifest.get("kwargs", None)

                    if "cmd" in manifest:
                        cmd = manifest["cmd"](
                            target, manifest.get("deps", None), **kwargs)

                        return_code = run(cmd)
                        if return_code != 0:
                            raise ResourceBuildException(
                                "Required resource dependency %s could not be built, "
                                "return code %d." % (target_path, return_code))
                    else:
                        manifest["f"](target, manifest.get("deps", None), **kwargs)

        build(target)


    def minify_path(self, deps, cwd, static_path, target, debug=None):
        self.minify_build(deps, cwd, static_path, target, debug=debug)
        resource_hash = self.sha1_hex((static_path / target).read_text())
        return f"{str(target)}?v={resource_hash[:7]}"

    # Initialisation


    def init_env(self):
        # Dotenv files will only be sought in the current working directory.
        load_env_app(Path("."), mode=self.settings.options.mode)

        if self.settings.options.mode:
            self.add_stat("Mode", self.settings.options.mode)


    def init_settings(self, options):
        self.settings.options = options
        self.init_env()
        self.settings.app = {}
        self.settings.app.log = {}

        self.label = self.defined("label")
        if self.label:
            self.add_stat("Label", self.label)

        self.settings.debug = self.defined("debug", type=bool)
        if self.settings.debug:
            self.add_stat("Debug", True)

        self.settings.port = self.defined("port", type=int)
        self.add_stat("Address", f"http://localhost:{self.settings.port}")

        self.settings.cors = self.defined("cors")
        if self.settings.cors:
            self.add_stat("CORS", self.settings.cors)



    def __init__(self, handlers, options, **settings):
        """
        Order of precedence:

        -   `options` - command line options
        -   `settings` - app defaults
        """

        assert self.name
        assert self.title

        self.init_stats()

        self.settings = Settings(settings or {})
        self.init_settings(options)

        if self.defined("color") == "ansi":
            root_handler = app_log.parent.handlers[0]
            formatter = root_handler.formatter
            formatter._colors = {
                10: '\x1b[34m',
                20: '\x1b[32m',
                30: '\x1b[33m',
                40: '\x1b[31m'
            }
            formatter._normal = "\033[0m"

        log_dir = self.defined("log_dir")
        self.init_log("uri", log_dir=log_dir, propagate=False, level=logging.INFO)
        self.init_log("tornado", log_dir=log_dir)

        if self.defined("status", bool):
            handlers.insert(1, (r"/server-status", ServerStatusHandler))
            self.init_response_log(self.settings.app)

        _settings = self.settings
        # Resets `self.settings`:
        super().__init__(handlers, **self.settings)
        self.settings = _settings

        self.write_stats()



class StaticFileHandler(tornado.web.StaticFileHandler):
    # Keep up to date with `tornado.web`
    # pylint: disable=broad-except,using-constant-test

    def get(self, *args, **kwargs):
        if self.settings.cors == "all":
            self.set_header("Access-Control-Allow-Origin", "*")
        return super().get(*args, **kwargs)

    def options(self, *args, **kwargs):
        method_list = ("get", "head", "options")
        methods_available = set(dir(self)) & set(method_list)
        allow = ",".join([v.upper() for v in methods_available])
        if self.settings.cors == "all":
            self.set_header("Allow", allow)
            self.set_header("Access-Control-Allow-Origin", "*")
            self.set_header("Access-Control-Allow-Headers", "X-Requested-With")



class GenerateFileHandler(StaticFileHandler):
    # Override
    def generate(self, path, abspath):
        raise NotImplementedError

    def initialize(self, path, default_filename=None):
        self.root = os.path.abspath(path) + os.path.sep
        self.default_filename = default_filename

    def get(self, path, include_body=True):
        path = self.parse_url_path(path)
        abspath = os.path.abspath(os.path.join(self.root, path))
        # os.path.abspath strips a trailing /
        # it needs to be temporarily added back for requests to root/
        if not (abspath + os.path.sep).startswith(self.root):
            raise tornado.web.HTTPError(403, "%s is not in root static directory", path)
        if os.path.isdir(abspath) and self.default_filename is not None:
            # need to look at the request.path here for when path is empty
            # but there is some prefix to the path that was already
            # trimmed by the routing
            if not self.request.path.endswith("/"):
                self.redirect(self.request.path + "/")
                return
            abspath = os.path.join(abspath, self.default_filename)

        #---
        if not os.path.exists(abspath):
            self.generate(path, abspath)
        #---

        if not os.path.exists(abspath):
            raise tornado.web.HTTPError(404)
        if not os.path.isfile(abspath):
            raise tornado.web.HTTPError(403, "%s is not a file", path)

        stat_result = os.stat(abspath)
        modified = datetime.datetime.fromtimestamp(stat_result[stat.ST_MTIME])

        self.set_header("Last-Modified", modified)

        mime_type, _encoding = mimetypes.guess_type(abspath)
        if mime_type:
            self.set_header("Content-Type", mime_type)

        cache_time = self.get_cache_time(path, modified, mime_type)
        if cache_time > 0:
            self.set_header("Expires", datetime.datetime.now(datetime.UTC) + \
                                       datetime.timedelta(seconds=cache_time))
            self.set_header("Cache-Control", "max-age=" + str(cache_time))
        else:
            self.set_header("Cache-Control", "public")

        self.set_extra_headers(path)

        # Check the If-Modified-Since, and don't send the result if the
        # content has not been modified
        ims_value = self.request.headers.get("If-Modified-Since")
        if ims_value is not None:
            date_tuple = email.utils.parsedate(ims_value)
            if_since = datetime.datetime.fromtimestamp(time.mktime(date_tuple))
            if if_since >= modified:
                self.set_status(304)
                return

        with open(abspath, "rb") as fp:
            data = fp.read()

            if not hasattr(self, "etag") or self.etag:
                hasher = hashlib.sha1()
                hasher.update(data)
                self.set_header("Etag", '"%s"' % hasher.hexdigest())

            if include_body:
                self.write(data)
            else:
                assert self.request.method == "HEAD"
                self.set_header("Content-Length", len(data))



class BaseHandler(tornado.web.RequestHandler):
    def _get_uhost(self):
        proto = self.request.headers.get(
            "X-Forwarded-Proto", None)

        host = self.request.headers.get(
            "X-Forwarded-Host", None)

        if host:
            port = self.request.headers.get(
                "X-Forwarded-Port", None)
            if port:
                host += ":{port:d}"

        return Host(
            proto or self.request.protocol,
            host or self.request.host,
        )


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.start = None
        self.profile = None

        # `self.url_root_full` may or may not contain a host.
        self.url_root_full = self.request.headers.get("X-Forwarded-Root", "")
        if self.url_root_full.endswith("/"):
            app_log.error(
                "X-Forwarded-Root may not end with a slash `%s` `%s`.",
                self.url_root_full, self.request.uri)
            raise tornado.web.HTTPError(400)

        # `self.url_root` does not contain a host.
        self.url_root = urllib.parse.urlparse(self.url_root_full).path

        self.uhost = self._get_uhost()

        sys.stdout.flush()


    def set_default_headers(self):
        if self.settings.cors == "all":
            self.set_header("Access-Control-Allow-Origin", "*")


    def write_error(self, status_code: int, **kwargs: Any) -> None:
        if "exc_info" in kwargs:
            (exc_type, exc, traceback) = kwargs["exc_info"]

            if isinstance(exc, HttpJsonException):
                self.set_header("Content-Type", "text/plain")
                self.write(json.dumps(exc.error_data, indent=2))
                self.finish()
                return

            if isinstance(exc, HttpRedirectException):
                self.set_header("Location", exc.location)
                self.finish()
                return

        super().write_error(status_code, **kwargs)


    def options(self, *args, **kwargs):
        method_list = ("get", "post", "head", "put", "delete", "options")
        methods_available = set(dir(self)) & set(method_list)
        allow = ",".join([v.upper() for v in methods_available])
        self.set_header("Allow", allow)

        if self.settings.cors == "all":
            self.set_header("Access-Control-Allow-Methods", allow)
            self.set_header("Access-Control-Allow-Headers", ",".join([
                "X-Forwarded-Proto",
                "X-Forwarded-Host",
                "X-Forwarded-Port",
                "X-Requested-With",
                "Authorization",
                "Content-Type",
            ]))


    # Utilities

    @property
    def settings(self):
        return self.application.settings

    # Profile

    def profile_start(self, name=None):
        name = name or ""
        if not name:
            self.profile = {
                "_epoch": time.time()
            }
        start = round(time.time() - self.profile["_epoch"], PROFILE_PRECISION)
        if name not in self.profile:
            self.profile[name] = {
                "start": start,
                "end": None,
                "total": None,
                "marks": []
            }
        self.profile[name]["marks"].append(["start", start])


    def profile_end(self, name=None):
        name = name or ""
        if name not in self.profile:
            app_log.warning("Profile '%s' not started.", name)
            return
        end = round(time.time() - self.profile["_epoch"], PROFILE_PRECISION)
        self.profile[name]["marks"].append(["end", end])
        self.profile[name]["end"] = end
        self.profile[name]["total"] = (self.profile[name]["end"] -
                                       self.profile[name]["start"])


    def profile_dump(self):
        self.profile_end()
        return self.profile


    def print_profile(self):
        print(pformat(self.profile_dump))


    # Lifecycle

    def prepare(self):
        self.start = time.time()
        self.profile_start()

    def _firma_http_unsupported_methods(self):
        if self._firma_unsupported_methods and (
                True in self._firma_unsupported_methods or \
                self.request.method.lower() in self._firma_unsupported_methods
        ):
            code, message = self._firma_unsupported_method_error
            raise tornado.web.HTTPError(code, message)


    # Copied from tornado.web. Keep updated
    # pylint: disable=bad-continuation,broad-except
    # Accept code from tornado that doesn't pass lint
    async def _execute(
        self, transforms: List["OutputTransform"], *args: bytes, **kwargs: bytes
    ) -> None:
        """Executes this request with the given output transforms."""
        self._transforms = transforms

        if hasattr(self, "_firma_http_extra_methods"):
            self._firma_http_extra_methods()

        try:
            if self.request.method not in self.SUPPORTED_METHODS:
                raise tornado.web.HTTPError(405)

            if hasattr(self, "_firma_unsupported_methods"):
                self._firma_http_unsupported_methods()

            if hasattr(self, "_firma_request_hook"):
                self._firma_request_hook()

            self.path_args = [self.decode_argument(arg) for arg in args]
            self.path_kwargs = dict(
                (k, self.decode_argument(v, name=k)) for (k, v) in kwargs.items()
            )

            if hasattr(self, "_firma_process_args"):
                self.path_args = self._firma_process_args(self.path_args)

            # If XSRF cookies are turned on, reject form submissions without
            # the proper cookie
            if self.request.method not in (
                "GET",
                "HEAD",
                "OPTIONS",
            ) and self.application.settings.get("xsrf_cookies"):
                self.check_xsrf_cookie()

            result = self.prepare()
            if result is not None:
                result = await result
            if self._prepared_future is not None:
                # Tell the Application we've finished with prepare()
                # and are ready for the body to arrive.
                future_set_result_unless_cancelled(self._prepared_future, None)
            if self._finished:
                return

            if _has_stream_request_body(self.__class__):
                # In streaming mode request.body is a Future that signals
                # the body has been completely received.  The Future has no
                # result; the data has been passed to self.data_received
                # instead.
                try:
                    await self.request._body_future
                except iostream.StreamClosedError:
                    return

            method = getattr(self, self.request.method.lower())
            result = method(*self.path_args, **self.path_kwargs)
            if result is not None:
                result = await result
            if self._auto_finish and not self._finished:
                self.finish()

        # Edit start - Think this is to catch MySQL errors?
        except IOError as e:
            print('ioerror')
            raise e
        except AssertionError as e:
            print('assertionerror')
            raise e
        # Edit end

        except Exception as e:
            try:
                self._handle_request_exception(e)
            except Exception:
                app_log.error("Exception in exception handler", exc_info=True)
            finally:
                # Unset result to avoid circular references
                result = None
            if self._prepared_future is not None and not self._prepared_future.done():
                # In case we failed before setting _prepared_future, do it
                # now (to unblock the HTTP server).  Note that this is not
                # in a finally block to avoid GC issues prior to Python 3.4.
                self._prepared_future.set_result(None)


    def on_finish(self):
        if not hasattr(self, "start") or self.start is None:
            return
        now = time.time()
        duration = now - self.start
        self.settings.app.log.uri.log.info(
            "%s, %s, %s, %s, %0.3f",
            str(now),
            self.request.uri,
            self.request.remote_ip,
            repr(self.request.headers.get("User-Agent", "User-Agent")),
            duration
        )

        if self.settings.app.response_log is not None:
            response = [now, self._status_code, duration]
            self.settings.app.response_log.append(response)


    # Cookies

    def cookie_name(self, name):
        return "-".join([_f for _f in [
            self.settings.app.cookie_prefix, name] if _f])


    def app_set_cookie(self, key, value, **kwargs):
        """
        Uses app prefix and URL root for path.
        Stringify as JSON. Always set secure.
        """

        kwargs = dict(list({
            "path": self.url_root
        }.items()) + list((kwargs or {}).items()))

        # A falsy path will cause cookie to not match any URLs
        if "path" in kwargs and not kwargs["path"]:
            del kwargs["path"]

        key = self.cookie_name(key)
        value = json.dumps(value)

        self.set_secure_cookie(key, value, **kwargs)


    def app_get_cookie(self, key, secure=True):
        "Uses app prefix. Secure by default. Parse JSON."

        key = self.cookie_name(key)

        if secure:
            # Returns `bytes`
            value = self.get_secure_cookie(key)
            if value:
                value = value.decode()
        else:
            # Returns `str`
            value = self.get_cookie(key)

        return value and json.loads(value)


    def app_clear_cookie(self, key, **kwargs):
        """
        Uses app prefix and URL root for path.
        """

        kwargs = kwargs or {}
        kwargs.update({
            "path": self.url_root
        })

        self.clear_cookie(self.cookie_name(key), **kwargs)


    # Sessions

    """
    `Session` type should be a SQLAlchemy model like so:

    class Session(Base):
        ...

        session_id = Column(Integer, primary_key=True)
        delete_time = Column(Float)
        ip_address = Column(String, nullable=False)
        accept_language = Column(String, nullable=False)
        user_agent = Column(String, nullable=False)
        user = relationship(User, backref='session_list')
        auth = relationship(User, backref='session_list')

        def __init__(
            self, user, auth,
            ip_address=None, accept_language=None, user_agent=None
        ):
        ...

    """  # pylint: disable=pointless-string-statement

    def get_accept_language(self):
        return self.request.headers.get("Accept-Language", "")

    def get_user_agent(self):
        return self.request.headers.get("User-Agent", "")

    def start_session(self, value):
        self.app_set_cookie(
            "session", value,
            path=self.application.SESSION_COOKIE_PATH,
            samesite="lax",  # Cannot use OAuth with `strict`.
        )

    def end_session(self):
        self.app_clear_cookie(
            "session", path=self.application.SESSION_COOKIE_PATH)

    def create_session(self, user, auth, Session):
        # pylint: disable=invalid-name
        # `Session` is a class.

        session = Session(
            user,
            auth,
            self.request.remote_ip,
            self.get_accept_language(),
            self.get_user_agent(),
        )
        self.orm.add(session)
        self.orm.flush()

        self.orm.commit()

        self.start_session(str(session.session_id))

        return session

    def compare_session(self, session):
        """
        Returns falsy if equal, truthy if different.
        """
        return \
            session.ip_address not in (
                self.request.remote_ip,
                self.request.headers.get("X-Remote-Addr", None)
            ) or \
            session.accept_language != self.get_accept_language() or \
            session.user_agent != self.get_user_agent()

    def get_session(self, Session):
        # pylint: disable=invalid-name
        # `Session` is a class.

        session_id = self.app_get_cookie("session")

        try:
            session_id = int(session_id)
        except (ValueError, TypeError):
            return None

        try:
            session = self.orm.query(Session).\
                filter_by(session_id=session_id).one()
        except NoResultFound:
            self.end_session()
            return None

        if session.delete_time is not None:
            self.end_session()
            return None

        if self.compare_session(session):
            self.end_session()
            return None

        session.touch_commit()

        return session



    # Arguments

    def get_argument_int(self, name, default):
        """
        Returns a signed integer, or
        `default` if value cannot be converted.
        """
        value = self.get_argument(name, default)
        try:
            value = int(value)
        except (ValueError, TypeError):
            value = default
        return value

    def get_argument_date(self, name, default, end=None):
        """
        Returns a date (year, month, day) based on a variable-length
        string. If `end` is falsy, returns the earliest possible date,
        ie. "2011" returns "1st of January 2011", otherwise, returns
        the day after the latest possible date, eg. "2012-08" returns
        "2012-09-01".
        """
        value = self.get_argument(name, default)
        if not value:
            return default

        match = re.compile("""^
        ([0-9]{4})
        (?:
        -([0-9]{2})
        (?:
        -([0-9]{2})
        )?
        )?""", re.U | re.X).match(value)

        if not match:
            return default

        match = [v and int(v) for v in match.groups()]

        delta = None

        if end:
            if match[1] is None:
                delta = relativedelta(years=1)
            elif match[2] is None:
                delta = relativedelta(months=1)
            else:
                delta = relativedelta(days=1)
        if match[1] is None:
            match[1] = 1
            match[2] = 1
        elif match[2] is None:
            match[2] = 1

        vdate = datetime.date(*match)

        if delta:
            vdate += delta

        return vdate

    def get_argument_int_set(self, name):
        """
        Returns a list of unique signed integers. They may
        be supplied as multiple and/or comma-separated parameters
        """

        values = set([])
        raw = self.get_arguments(name)
        for text in raw:
            for part in text.split(","):
                try:
                    id_ = int(part)
                except ValueError:
                    continue
                values.add(id_)
        return sorted(list(values))



class AuthPasswordOtpMixin():
    def get_login_arguments(self, user_id_key):
        args = {
            user_id_key: self.get_argument(user_id_key, None),
            "password": self.get_argument("password", None),
            "token": self.get_argument("token", None),
            "next": self.get_argument("next", "/"),
        }

        missing = [k for k, v in args.items() if not(v)]
        if missing:
            raise tornado.web.HTTPError(
                400, "Values for %s are required." % ", ".join(missing))

        return args


    def verify_user(self, user, args):
        if not user.verify_password_hash(args["password"]):
            raise tornado.web.HTTPError(401, "Unauthorized")

        if not user.verify_onetimepass(args["token"]):
            raise tornado.web.HTTPError(401, "Unauthorized")



class AuthFirmaOAuth2Mixin():
    @classmethod
    def conf_settings(cls, env):
        return {
            cls._OAUTH_SETTINGS_KEY: {
                "key": env[f"{cls._ENV_SETTINGS_KEY}_CLIENT_ID"],
                "secret": env[f"{cls._ENV_SETTINGS_KEY}_CLIENT_SECRET"],
            },
        }


    def get_login_url(self):
        login_resource = self.get_login_resource()

        if "?" in login_resource:
            raise Exception()

        scheme = self.request.headers.get("X-Forwarded-Proto", self.request.protocol)
        host = self.request.headers.get("X-Forwarded-Host", self.request.host)
        port = self.request.headers.get("X-Forwarded-Port", None)

        login_host = f"{scheme}://{host}"
        if port:
            login_host += f":{port}"
        login_url = login_host + login_resource

        return login_url


    async def get(self):
        login_url = self.get_login_url()
        code = self.get_argument('code', None)

        if code is None:
            self.authorize(login_url)
        else:
            await self.authenticate(code, login_url)



class AuthGoogleOAuth2UserMixin(tornado.auth.GoogleOAuth2Mixin, AuthFirmaOAuth2Mixin):
    _ENV_SETTINGS_KEY = "GOOGLE_OAUTH"
    _OAUTH_SETTINGS_KEY = "google_oauth"


    async def _oauth_get_user_future(
        self, access_token: Dict[str, Any]
    ) -> Dict[str, Any]:
        http = self.get_auth_http_client()
        url = self._OAUTH_USERINFO_URL + "?" + urllib.parse.urlencode({
            "access_token": access_token["access_token"]
        })
        response = await http.fetch(url)
        return escape.json_decode(response.body)


    async def get_authenticated_user(
        self, redirect_uri: str, code: str
    ) -> Dict[str, Any]:
        access_token = await super().get_authenticated_user(redirect_uri, code)
        user_data = await self._oauth_get_user_future(access_token)
        return user_data



class AuthWordpressOAuth2UserMixin(tornado.auth.OAuth2Mixin, AuthFirmaOAuth2Mixin):
    _ENV_SETTINGS_KEY = "WP_OAUTH"
    _OAUTH_SETTINGS_KEY = "wp_oauth"

    async def _oauth_get_user_future(
        self, access_token: Dict[str, Any]
    ) -> Dict[str, Any]:
        http = self.get_auth_http_client()
        url = self._OAUTH_USERINFO_URL + "?" + urllib.parse.urlencode({
            "access_token": access_token["access_token"]
        })
        response = await http.fetch(url)
        return escape.json_decode(response.body)


    async def get_authenticated_user(
            self,
            redirect_uri: str,
            code: str
    ) -> Dict[str, Any]:
        http = self.get_auth_http_client()
        body = urllib.parse.urlencode({
            "redirect_uri": redirect_uri,
            "code": code,
            "client_id": self.settings[self._OAUTH_SETTINGS_KEY]["key"],
            "client_secret": self.settings[self._OAUTH_SETTINGS_KEY]["secret"],
            "grant_type": "authorization_code",
        })

        try:
            response = await http.fetch(
                self._OAUTH_ACCESS_TOKEN_URL,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                body=body,
            )
        except tornado.httpclient.HTTPClientError as e:
            message = e.response.body
            app_log.error(message)
            raise
        access_token = escape.json_decode(response.body)

        user_data = await self._oauth_get_user_future(access_token)
        return user_data



class SecondaryDatabaseMixin(object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._db_table_cache = {}

    def _connected(self, key, name, warn=True):
        if not self.application.mysql_db_name(key):
            if warn:
                app_log.warning("Database '%s' ('%s') not linked", key, name)
            return False

        if not self.application.mysql_db_connected(key):
            if warn:
                app_log.warning("Database '%s' ('%s') not connected", key, name)
            return False

        return True

    def _assert_linked(self, key, name):
        if not self._connected(key, name, warn=True):
            raise tornado.web.HTTPError(400)

    def _table(self, schema, name, *args, **kwargs):
        key = "%s_%s" % (schema, name)
        if key not in self._db_table_cache:
            # `org_id` is ambiguous if not aliased
            self._db_table_cache[key] = aliased(Table(
                name,
                MetaData(),
                *args,
                schema=schema,
                **kwargs
            ))
        return self._db_table_cache[key]



class UserMixin(object):
    """
    Client class should be a SQLAlchemy model with the
    follosing attributes, eg.:

    HASH_ALG = hashlib.sha256
    SALT_LENGTH = 7
    SECRET_LENGTH = 16

    password_hash = Column(LONGTEXT(
        length=USER_HASH_ALG().digest_size * 2,
        charset="latin1",
        collation="latin1_swedish_ci"
    ))
    onetime_secret = Column(LONGTEXT(
        length=16,
        charset="latin1",
        collation="latin1_swedish_ci"
    ))
    """

    # pylint: disable=not-callable

    HASH_ALG = None
    SALT_LENGTH = None
    SECRET_LENGTH = None

    def set_password_hash(self, plaintext):
        """
        `plaintext` is UTF-8 encoded
        """
        hasher = self.HASH_ALG()
        hex_length = hasher.digest_size * 2
        hasher.update(os.urandom(hex_length))
        salt = hasher.hexdigest()[:self.SALT_LENGTH]
        payload = (salt + plaintext).encode("utf-8")

        hasher = self.HASH_ALG()
        hash_ = self.HASH_ALG(payload).hexdigest()
        salted_hash = (salt + hash_)[:hex_length]
        self.password_hash = salted_hash

    def verify_password_hash(self, plaintext):
        """
        `plaintext` is UTF-8 encoded
        Returns `True` if plaintext matches hash.
        """
        if not self.password_hash:
            return None

        salt = self.password_hash[:self.SALT_LENGTH]
        payload = (salt + plaintext).encode("utf-8")

        hasher = self.HASH_ALG()
        hex_length = hasher.digest_size * 2
        hash_ = self.HASH_ALG(payload).hexdigest()
        salted_hash = (salt + hash_)[:hex_length]
        return self.password_hash == salted_hash

    def set_onetime_secret(self):
        secret = base64.b32encode(os.urandom(10))
        self.onetime_secret = secret
        return secret

    def verify_onetimepass(self, token):
        if not self.password_hash:
            return None

        return valid_totp(token, self.onetime_secret)



class ServerStatusHandler(tornado.web.RequestHandler):
    @staticmethod
    def median_sorted(data):
        if not data:
            return None

        if len(data) == 1:
            return data[0]

        half = int(len(data) / 2)
        if len(data) % 2:
            return (data[half - 1] +
                    data[half]) / 2

        return data[half]

    @staticmethod
    def quartiles(data):
        """
        Accepts an unsorted list of floats.
        """
        if not data:
            return None

        sample = sorted(data)

        if len(data) == 1:
            median = data[0]
            q1 = data[0]
            q3 = data[0]
        else:
            median = ServerStatusHandler.median_sorted(sample)
            half = int(len(data) / 2)
            if len(data) % 2:
                q1 = (
                    ServerStatusHandler.median_sorted(
                        sample[:half]) +
                    ServerStatusHandler.median_sorted(
                        sample[:half + 1])
                ) / 2
                q3 = (
                    ServerStatusHandler.median_sorted(
                        sample[half:]) +
                    ServerStatusHandler.median_sorted(
                        sample[half + 1:])
                ) / 2
            else:
                q1 = ServerStatusHandler.median_sorted(
                    sample[:half])
                q3 = ServerStatusHandler.median_sorted(
                    sample[half:])

        return {
            "q1": median if q1 is None else q1,
            "median": median,
            "q3": median if q3 is None else q3
        }

    def get(self):
        if self.settings.app.response_log is None:
            raise tornado.web.HTTPError(404)

        response = {
            "1": 0,
            "2": 0,
            "3": 0,
            "4": 0,
            "5": 0,
        }
        duration = {
            "min": 0,
            "q1": 0,
            "median": 0,
            "q3": 0,
            "max": 0,
        }

        self.application.trim_response_log()

        min_ = None
        max_ = None

        for (
                _timestamp, status_code, duration_
        ) in self.settings.app.response_log:
            if min_ is None:
                min_ = duration_
                max_ = duration_
            else:
                min_ = min(min_, duration_)
                max_ = max(max_, duration_)

            k = str(status_code)[0]
            response[k] += 1

        if min_ is not None:
            duration["min"] = min_
            duration["max"] = max_
            try:
                duration.update(self.quartiles([
                    v[2] for v in self.settings.app.response_log]))
            except TypeError:
                sys.stderr.write(
                    "Failed quartiles: %s" %
                    repr([v[2] for v in self.settings.app.response_log]))
                sys.stderr.flush()
                raise

        data = {
            "label": self.application.label or self.application.title,
            "response": response,
            "duration": duration,
        }

        self.set_header("Access-Control-Allow-Origin", "*")
        self.set_header("Content-Type", "application/json; charset=UTF-8")
        self.write(json.dumps(data))
