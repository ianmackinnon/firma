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

"""
Pytest plugin to be imported by `conftest.py`.
"""

# pylint: disable=redefined-outer-name

import re
import json
import copy
import time
import logging
import datetime
import urllib.parse
from pathlib import Path
from subprocess import Popen, PIPE

import requests

import pytest

from firma.browser import SeleniumDriver



LOG = logging.getLogger("pytest_firma")



DURATION = {}
VC_ID = None
DURATION_LOG = None



# Exceptions



class HttpConnectionError(Exception):
    def __init__(self, message, url, *args, **kwargs):
        super().__init__(message, *args, **kwargs)
        LOG.error("Host unreachable: %s" % url)
        pytest.exit("Host unreachable")



def get_vc_id():
    cmd = """\
echo $(git rev-parse --short HEAD)\
$(if ! git diff-files --quiet; then echo -dirty; fi)\
"""
    process = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    (out, err) = process.communicate()
    out = out.decode("utf-8")
    err = err.decode("utf-8")

    if out:
        match = re.compile(r"^([0-f]{7,32}(:?-dirty)?)").match(out)
        if match:
            return match.group(0)
        LOG.warning(out)

    if err:
        LOG.error(err)

    return None



def get_duration_log(log_dir):
    if not VC_ID:
        return
    timestamp = datetime.datetime.utcnow().strftime("%Y-%m-%d.%H-%M-%S.utc")

    log_path = Path(log_dir)
    file_path = log_path / f"test.{timestamp}.{VC_ID}.log"

    log_path.mkdir(exist_ok=True)
    LOG.info("Opening duration log %s", file_path.resolve())
    return open(file_path, "w", encoding="utf-8")



# Pytest functions



def pytest_addoption(parser):
    parser.addoption("--base-url", action="store")
    parser.addoption("--driver", action="store")
    parser.addoption("--driver-path", action="store")
    parser.addoption("--profile", action="store_true")
    parser.addoption("--server-retry", action="store_true")
    parser.addoption("--hide-header", action="store_true")
    parser.addoption("--show-browser", action="store_true")
    parser.addoption("--keep-browser", action="store_true")
    parser.addoption("--keep-browser-always", action="store_true")
    parser.addoption("--geometry", action="store", default="1600x1200+2100+120")
    parser.addoption("--socks5-proxy", action="store")
    parser.addoption("--ssl-cert", action="append")
    parser.addoption("--credentials", action="store")
    parser.addoption("--log-dir", action="store")



def pytest_sessionstart(session):
    global VC_ID, DURATION_LOG

    VC_ID = get_vc_id()
    if session.config.option.log_dir:
        DURATION_LOG = get_duration_log(session.config.option.log_dir)

    if session.config.option.hide_header:
        session.verbose = session.config.option.verbose
        session.config.option.verbose = -1

    ssl_cert_list = session.config.getoption("--ssl-cert")
    if ssl_cert_list:
        ssl_cert_lookup = []
        for item in ssl_cert_list:
            (pattern, cert_path) = item.split(" = ")
            regex = re.compile(pattern)
            cert_path = Path(cert_path)

            assert cert_path.exists()

            ssl_cert_lookup.append({
                "regex": regex,
                "path": cert_path,
            })

        session.config.option.ssl_cert_lookup = ssl_cert_lookup



def pytest_runtestloop(session):
    if session.config.option.hide_header:
        verbose = session.verbose
        session.config.option.verbose = verbose
        del session.verbose



@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    setattr(item, "report_" + report.when, report)
    return report



def pytest_runtest_logstart(nodeid, location):
    global DURATION
    DURATION[nodeid] = time.time()



def pytest_report_teststatus(report, config):
    write_to_log = DURATION_LOG and not config.option.keep_browser
    if config.option.profile or write_to_log:
        if report.when == "teardown" and report.outcome == "passed":
            duration = time.time() - DURATION[report.nodeid]
            cache = "" #"not-cached" if config.option.no_cache else "maybe-cached"

            if config.option.profile:
                LOG.info("Duration (%s) %0.3f", cache, duration)
            if write_to_log:
                DURATION_LOG.write(f"{report.nodeid} {cache} {duration:0.3f}\n")
                DURATION_LOG.flush()



def pytest_collection_modifyitems(session, config, items):
    # Make sure server status test gets called first so HTTP tests
    # are skipped if the server is not available.
    #
    # Run fast API tests before slow Selenium tests

    items.sort(key=(lambda item: (
        "server_status" not in item.name,
        "selenium" in item.fixturenames
    )))



@pytest.fixture(scope="session")
def base_url(request):
    return request.config.option.base_url



@pytest.fixture(scope="session")
def sensitive_url(request, base_url):
    return False



@pytest.fixture(scope="session")
def credentials(request):
    path = Path(request.config.option.credentials)
    data = json.loads(path.read_text())
    return data



# Requests fixtures



def request_kwargs_dev(url, ptreq=None, **kwargs):
    if kwargs is None:
        kwargs = {}
    else:
        kwargs = copy.deepcopy(kwargs)

    kwargs["allow_redirects"] = False

    if ptreq and hasattr(ptreq.config.option, "ssl_cert_lookup"):
        for item in ptreq.config.option.ssl_cert_lookup:
            if item["regex"].search(url):
                kwargs["verify"] = str(item["path"])
                break
        else:
            kwargs.pop("verify", None)
    else:
        kwargs.pop("verify", None)


    if ptreq and hasattr(ptreq.config.option, "socks5_proxy"):
        proxy = ptreq.config.option.socks5_proxy

        if proxy:
            kwargs["proxies"] = {
                "http": f"socks5://{proxy}",
                "https": f"socks5://{proxy}"
            }
        else:
            kwargs.pop("proxies", None)
    else:
        kwargs.pop("proxies", None)

    return kwargs



def _http_request(
        url,
        retry=False, timeout=None, profile=False, ptreq=None, redirect=True,
        **kwargs
):
    session = requests.Session()

    if retry:
        retries = Retry(
            total=10,
            backoff_factor=0.5,
            status_forcelist=[500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retries)

        session.mount('http://', adapter)
        session.mount('https://', adapter)

    if timeout is not None:
        kwargs["timeout"] = timeout

    if timeout is not None:
        kwargs["timeout"] = timeout

    while True:
        # `requests` only allows a single certificate to be supplied.
        # For requests to the dev server we need to use a custom certificate
        # for the initial request, but default certificates for the
        # redirect location, so we must handle redirection ourselves.

        k2 = request_kwargs_dev(url, ptreq=ptreq, **kwargs)
        try:
            response = session.get(url, **k2)
        except (
                requests.exceptions.ConnectionError,
                requests.exceptions.RetryError,
                requests.exceptions.SSLError,
        ) as e:
            raise HttpConnectionError(
                f"Host unreachable ({str(e)})", url=url) from None

        if response.status_code == 503:
            raise HttpConnectionError(
                "Host unreachable (proxy)", url=url) from None

        if (300 <= response.status_code <= 399) and redirect:
            location = response.headers.get("Location")
            if not location.startswith("http"):
                location = urllib.parse.urljoin(url, location)
            url = location
            LOG.debug(f"Redirecting to {url}")
            continue

        break

    return response



@pytest.fixture(scope="session")
def http_request():
    yield _http_request



@pytest.fixture(scope="session")
def get_json_params_hook(request):
    """
    Overload this to transform parameters before passing to Requests.
    """
    def transform(params):
        return params

    return transform



@pytest.fixture(scope="session")
def get_json(request, http_request, get_json_params_hook):
    """
    Used to get a successful JSON response from an application resource
    """

    def f(url, retry=False, timeout=None, assert_status_code=None, **kwargs):

        kwargs["params"] = get_json_params_hook(kwargs.get("params", None))

        if request.config.option.profile:
            LOG.info(url)

        response = http_request(
            url,
            retry=retry, timeout=timeout,
            profile=request.config.option.profile,
            ptreq=request,
            **kwargs
        )

        if assert_status_code is not None:
            assert response.status_code == assert_status_code
            return

        try:
            data = response.json()
        except json.decoder.JSONDecodeError:
            LOG.error("%s: response not JSON", url)
            raise
        return data

    yield f



# Selenium fixtures


@pytest.fixture(scope="session")
def selenium_url_hook(request):
    "Overload this to transform URLs before passing to Selenium"

    def transform(url):
        return url

    return transform



@pytest.fixture
def selenium_function(request, selenium_url_hook):
    driver = SeleniumDriver(
        driver=None,
        **get_chrome_options(request)
    )

    LOG.debug("Default timeout: %.3f", driver._default_timeout)
    LOG.debug("Retry: %s", request.config.getoption("--server-retry"))

    get_orig = driver.get

    def get(url, *args, **kwargs):
        return get_orig(selenium_url_hook(url), *args, **kwargs)

    driver.get = get

    yield driver

    keep = False
    outcome = request.node.report_call.outcome

    if outcome not in ["passed", "skipped"]:
        screenshot_path = Path("/tmp") / f"{request.node.name}.png"
        driver.save_screenshot(str(screenshot_path))
        LOG.warning("Saved screenshot at failure: `%s`", screenshot_path)
        if request.config.getoption("--keep-browser"):
            keep = True
    if request.config.getoption("--keep-browser-always"):
        keep = True

    if keep:
        driver.keep(240)

    driver.close_if_open()


def get_chrome_options(request):
    options = {
        "socks5_proxy": request.config.option.socks5_proxy,
        "default_timeout": request.config.option.default_timeout,
        "geometry": request.config.option.geometry,
    }

    if (
            request.config.option.show_browser or
            request.config.option.keep_browser or
            request.config.option.keep_browser_always
    ):
        options["show"] = True

    return options



@pytest.fixture(scope="session")
def selenium_session(request, selenium_url_hook):
    driver = SeleniumDriver(
        driver=None,
        **get_chrome_options(request)
    )

    LOG.debug("Default timeout: %.3f" % driver._default_timeout)
    LOG.debug("Retry: %s" % request.config.getoption("--server-retry"))

    get_orig = driver.get

    def get(url, *args, **kwargs):
        return get_orig(selenium_url_hook(url), *args, **kwargs)

    driver.get = get

    yield driver

    keep = False

    if request.config.getoption("--keep-browser-always"):
        keep = True

    if keep:
        driver.keep(240)

    driver.close_if_open()




@pytest.fixture
def selenium(request, selenium_session):
    driver = selenium_session
    yield driver

    outcome = request.node.report_call.outcome

    if outcome not in ["passed", "skipped"]:
        screenshot_path = Path("/tmp") / f"{request.node.name}.png"
        driver.save_screenshot(str(screenshot_path))
        LOG.warning("Saved screenshot at failure: `%s`", screenshot_path)



def parametrize_dict(value_name, param_dict, **pd_kwargs):
    assert " " not in value_name

    (keys, values) = zip(*param_dict.items())

    values = copy.deepcopy(values)

    key_attr = pd_kwargs.get("key_attr", None)
    if key_attr:
        for i, value in enumerate(values):
            value[key_attr] = keys[i]

    return pytest.mark.parametrize(value_name, values, ids=keys, **pd_kwargs)



pytest.mark.parametrize_dict = parametrize_dict
