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
import shutil
import logging
import traceback
from typing import Union
from pathlib import Path
from tempfile import NamedTemporaryFile
from contextlib import contextmanager

import sqlparse
from dotenv import dotenv_values
from unidecode import unidecode



LOG = logging.getLogger("firma.util")



# Format



def format_traceback():
    _exc_type, _exc_value, exc_traceback = sys.exc_info()
    return "".join(traceback.format_tb(exc_traceback))



def format_slug(text):
    if not text:
        return None
    text = unidecode(text)
    text = text.lower()
    text = re.compile(r"['`\".]", re.U).sub(r"", text)
    text = re.compile(r"[\W\s]+", re.U).sub(r"-", text)
    text = text.strip("-")
    return text



def format_whitespace(
        text: str,
        multiline: Union[bool, None] = None
) -> str:
    re_whitespace = re.compile(r"\s+")

    if multiline:
        out = []
        for line in text.splitlines():
            line = format_whitespace(line)
            if line:
                out.append(line)
        return "\n".join(out)

    return re_whitespace.sub(" ", text).strip()



def format_commas(i):
    if i is None:
        return None
    s = str(int(i))
    o = str()
    while len(s) > 3:
        o = ',' + s[-3:] + o
        s = s[:-3]
    return s + o



def format_abbreviate(i):
    if i is None:
        return None

    i = float(i)

    def e(a, b):
        return a * 10 ** b

    for (abbr, n) in (
            ("tn", 12),
            ("bn", 9),
            ("m", 6),
            ("k", 3),
    ):

        if i >= e(1, n + 1):
            return u"%0.0f%s" % (i / e(1, n), abbr)
        if i >= e(1, n + 1) - e(5, n - 2):
            return u"%0.0f%s" % ((i + e(5, n - 2)) / e(1, n), abbr)
        if i >= e(1, n):
            return u"%0.1f%s" % (i / e(1, n), abbr)
        if i >= e(1, n) - e(5, n - 4):
            return u"%0.1f%s" % ((i + e(5, n - 4)) / e(1, n), abbr)

    return u"%d" % i



def format_sql(text) -> str:
    text = str(text)
    return sqlparse.format(text, reindent=True)



def format_sql_query(query) -> str:
    # This seems to reverse LIMIT parameters.
    params = query.statement.compile().params
    text = str(query)
    subs = []
    for match in re.compile(r"%\(([^)]*)\)s").finditer(text):
        subs.append((match.span(), params[match.group(1)]))
    for span, value in reversed(subs):
        text = text[:span[0]] + str(value) + text[span[1]:]
    text = format_sql(text)
    return text



# Logging



def color_log(log):
    color_red = '\033[91m'
    color_green = '\033[92m'
    color_yellow = '\033[93m'
    color_blue = '\033[94m'
    color_end = '\033[0m'

    level_colors = (
        ("error", color_red),
        ("warning", color_yellow),
        ("info", color_green),
        ("debug", color_blue),
    )

    safe = None
    color = None

    def xor(a, b):
        return bool(a) ^ bool(b)

    def _format(value):
        if isinstance(value, float):
            return "%0.3f"
        return "%s"

    def message_args(args):
        if not args:
            return "", []
        if (
                not isinstance(args[0], str) or
                xor(len(args) > 1, "%" in args[0])
        ):
            return " ".join([_format(v) for v in args]), args
        return args[0], args[1:]

    def _message(args, color):
        message, args = message_args(args)
        return "".join([color, message, color_end])

    def _args(args):
        args = message_args(args)[1]
        return args

    def build_lambda(safe, color):
        return lambda *args, **kwargs: getattr(log, safe)(
            _message(args, color), *_args(args), **kwargs)

    for (level, color) in level_colors:
        safe = "%s_" % level
        setattr(log, safe, getattr(log, level))
        setattr(log, level, build_lambda(safe, color))


def init_logs(*logs, args=None):
    offset = args.verbose - args.quiet if args else 0
    level = (
        logging.FATAL,
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        logging.DEBUG
    )[max(0, min(4, 2 + offset))]

    for log in logs:
        if not isinstance(log, logging.Logger):
            log = logging.getLogger(log)
        log.addHandler(logging.StreamHandler())
        log.setLevel(level)
        color_log(log)



# Configuration



def load_env_multi(path_list):
    return {k: v for path in path_list for k, v in dotenv_values(path).items()}



# IO



@contextmanager
def AtomicOutputFile(path: Union[Path, str], **kwargs):
    """
    Like a temporary file, but move to a desired permanent path
    if closed successful. Also create intermediate folders if necessary.
    """
    # pylint: disable=invalid-name
    # -   Matching capitalized `NamedTemporaryFile` `contextmanager` function

    path = Path(path)
    kwargs = {
        **kwargs,
        **{
            "delete": False,
        }
    }

    with NamedTemporaryFile("w", **kwargs) as temp:
        LOG.debug(
            "Opened temporary file `%s` for writing.",
            Path(temp.name).absolute())

        yield temp

        os.makedirs(path.parent, exist_ok=True)
        shutil.move(temp.name, path)
        LOG.info("Wrote `%s`", path.absolute())
