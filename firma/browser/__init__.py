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
import time
import base64
import shutil
import logging
from typing import Iterable, Union

import requests

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.wait import WebDriverWait
from selenium.common.exceptions import \
    NoSuchElementException, NoSuchWindowException, WebDriverException

from firma.pdf import write_compressed_pdf, write_header_pdf, write_headed_pdf, temp_path



LOG = logging.getLogger("firma.browser")

DEFAULT_CHROMEDRIVER_PATH_UBUNTU = "/usr/lib/chromium-browser/chromedriver"
DEFAULT_CHROMEDRIVER_PATH_SNAP = "/snap/bin/chromium.chromedriver"
DEFAULT_CHROMEDRIVER_PATH_DEBIAN = "/usr/bin/chromedriver"
DEFAULT_CHROMEDRIVER_PATH = DEFAULT_CHROMEDRIVER_PATH_UBUNTU
DEFAULT_TIMEOUT = 15



class WindowGeometry():
    def __init__(self, text):
        pattern = r"^([1-9][0-9]*)x([1-9][0-9]*)\+([0-9]+)\+([0-9]+)"

        match = re.compile(pattern).match(text.strip())
        if not match:
            raise ValueError(f"Could not parse window geometry string {text})")

        (self.width, self.height, self.x, self.y) = [int(v) for v in match.groups()]



class RenderError(Exception):
    pass

class RequiredElementNotFoundError(Exception):
    pass



# Helper functions

def xpath_class(text):
    return f'contains(concat(" ", normalize-space(@class), " "), " {text} ")'



# Driver class

class SeleniumDriver():
    """
    A wrapper for Selenium Chrome Driver.
    """

    @classmethod
    def get_driver(
            cls,
            chromedriver_path=None,
            show=None,
            devtools=None,
            geometry=None,
            socks5_proxy=None,
            chrome_options_extra=None,
    ):

        if chromedriver_path is None:
            chromedriver_path = DEFAULT_CHROMEDRIVER_PATH

        chrome_options = Options()

        if devtools:
            chrome_options.add_argument('--auto-open-devtools-for-tabs')

        if not show:
            chrome_options.add_argument("--headless")

        if socks5_proxy:
            chrome_options.add_argument(f"--proxy-server=socks5://{socks5_proxy}")

        if chrome_options_extra:
            for v in chrome_options_extra:
                chrome_options.add_argument(v)

        chrome_options.set_capability('goog:loggingPrefs', {
            "browser": "ALL",
        })

        service = Service(
            chromedriver_path
        )

        driver = webdriver.Chrome(
            options=chrome_options,
            service=service,
        )

        if geometry is not None:
            if not isinstance(geometry, WindowGeometry):
                geometry = WindowGeometry(geometry)
            driver.set_window_rect(
                geometry.x, geometry.y,
                geometry.width, geometry.height
            );

        driver._EXTRA_PDF_WARNING = False

        driver._show = show
        driver._devtools = devtools

        return driver


    def __init__(
            self,
            driver=None,
            default_timeout=None,
            chromedriver_path=None,
            show=None,
            devtools=None,
            geometry=None,
            socks5_proxy=None,
            on_create_callback=None,
            on_destroy_callback=None,
            chrome_options_extra=None,
    ):
        self._show = show
        self._devtools = devtools
        self._default_timeout = default_timeout
        self._chromedriver_path = chromedriver_path
        self._geometry = geometry
        self._socks5_proxy = socks5_proxy
        self._on_create_callback = on_create_callback
        self._on_destroy_callback = on_destroy_callback
        self._chrome_options_extra = chrome_options_extra
        self._js_log_buffer = []

        if self._default_timeout is None:
            self._default_timeout = DEFAULT_TIMEOUT

        self._issue_iframe_warning = self.iframe_unstable()

        self.start(driver)


    @property
    def driver_url(self):
        return self.command_executor._client_config.remote_server_addr


    def start(self, driver=None):
        if driver:
            self._driver = driver
        else:
            self._driver = SeleniumDriver.get_driver(
                self._chromedriver_path,
                show=self._show,
                devtools=self._devtools,
                geometry=self._geometry,
                socks5_proxy=self._socks5_proxy,
                chrome_options_extra=self._chrome_options_extra,
            )
            if self._on_create_callback:
                self._on_create_callback(self)

        self._driver.implicitly_wait(self._default_timeout)
        self.set_and_verify_implicit_timeout(self._default_timeout)


    def restart(self):
        self.destroy()
        self.start()


    def destroy(self):
        if self._on_destroy_callback:
            self._on_destroy_callback(self)

        try:
            self._driver.close()
        except (WebDriverException, NoSuchWindowException):
            pass


    def __getattr__(self, name):
        try:
            self.__getattribute__(name)
        except AttributeError:
            pass

        if name == "switch_to" and self._issue_iframe_warning:
            LOG.warning("Warning: Switching to an iframe is unstable when browser is visible and developer tools is open.")
            self._issue_iframe_warning = False

        return getattr(self._driver, name)


    def iframe_unstable(self):
        return self._show and self._devtools


    def get_timeout(self, key):
        """
        `key` should be one of 'implicit', 'pageLoad', 'script'.

        Timeout is:
        -   Returned from here in seconds
        -   Given by Selenium API in milliseconds
        -   Set by Selenium-Python in seconds
        """

        result = requests.get(f"{self.driver_url}/session/{self.session_id}/timeouts")

        timeouts = result.json()
        return timeouts["value"][key] / 1000


    def set_and_verify_implicit_timeout(self, timeout):
        self.implicitly_wait(timeout)
        result = self.get_timeout("implicit")
        assert result == timeout, \
            f"Set implicit timeout to `{timeout}`, but found set to `{result}`."


    def send_command(self, cmd, params=None):
        url = (
            f"{self.driver_url}"
            f"/session/{self.session_id}/chromium/send_command_and_get_result"
        )

        params2 = {
            "cmd": cmd,
            "params": params or {}
        }

        response = requests.post(url, json=params2)

        data = response.json()

        return data["value"]


    def _save_pdf_chromium(self, path, params=None):
        result = self.send_command("Page.printToPDF", params=params)

        if "error" in result:
            if self._show:
                LOG.warning("Cannot render PDFs when browser is visible")
            if "message" in result:
                LOG.error(result["message"])
            raise RenderError("Failed to print to PDF")

        data_base64 = result["data"]
        data = base64.b64decode(data_base64)

        with open(str(path), "wb") as fp:
            fp.write(data)
        LOG.debug("Saved PDF to %s", path)


    def save_pdf(self, path, params=None, recompress=None, headers=None):
        """
        `recompress` will recompress the output PDF
            (requires Ghostscript)
        `headers` may be a list of text headers to stamp onto the pages
            (requires Ghostscript and PDFTK)
        """

        prefix = path.stem
        pdf_path = temp_path(prefix=f"{prefix}.orig.", suffix=".pdf")
        self._save_pdf_chromium(pdf_path, params=params)

        if recompress:
            pdf_path_compressed = temp_path(prefix=f"{prefix}.compressed.", suffix=".pdf")
            write_compressed_pdf(pdf_path_compressed, pdf_path)
            os.remove(pdf_path)
            pdf_path = pdf_path_compressed

        if headers:
            pdf_path_headers = temp_path(prefix=f"{prefix}.headers.", suffix=".pdf")
            pdf_path_headed = temp_path(prefix=f"{prefix}.headed.", suffix=".pdf")

            write_header_pdf(pdf_path_headers, headers=headers)
            write_headed_pdf(pdf_path_headed, pdf_path, pdf_path_headers)
            os.remove(pdf_path_headers)
            os.remove(pdf_path)
            pdf_path = pdf_path_headed

        shutil.move(pdf_path, path)


    def find(
            self, selector,
            node=None, method="css", multiple=False, wait=None, required=False
    ):
        if wait is None or wait is True:
            # `if wait in (None, True)` returns `True` when `wait = 1` :(
            wait = self._default_timeout

        if wait is False:
            wait = 0

        if node is None:
            node = self._driver
        else:
            if method == "xpath" and selector.startswith("//"):
                LOG.warning(
                    "Node supplied to find function but "
                    "XPath selector starts with root node `//`. "
                    "`%s`"
                    "Did you mean to search for `descendant::`?", selector)

        by = {
            "css": By.CSS_SELECTOR,
            "xpath": By.XPATH,
        }[method]

        if wait != self._default_timeout:
            self._driver.implicitly_wait(wait)

        f_name = "find_elements" if multiple else "find_element"

        try:
            result = getattr(node, f_name)(by, selector)
        except NoSuchElementException:
            result = None

        if wait != self._default_timeout:
            self._driver.implicitly_wait(self._default_timeout)

        if required and not result:
            raise RequiredElementNotFoundError(
                f"No elements found for selector `{selector}`.")

        return result


    def find_all(self, *args, **kwargs):
        return self.find(multiple=True, *args, **kwargs)


    def scroll_to_view(self, element):
        """
        This is not reliable.
        """
        ActionChains(self).move_to_element(element).perform()


    def scroll_to_center(self, element):
        script = """
const rect = arguments[0].getBoundingClientRect();
window.scrollTo(
        (rect.left + window.pageXOffset) - (window.innerWidth / 2),
        (rect.top + window.pageYOffset) - (window.innerHeight / 2)
);
"""
        self.execute_script(script, element)


    def scroll_and_click(
            self,
            element,
            name=None,
            delay: [None, int, float] = None
    ):
        LOG.debug("Scrolling to link for %s...", name or element.text)
        self.scroll_to_center(element)
        LOG.debug("Done")

        if delay:
            LOG.debug("Sleeping %0.1fs...", delay)
            time.sleep(delay)
            LOG.debug("Done")

        LOG.debug("Clicking link for %s...", name or element.text)
        element.click()
        LOG.debug("Done")


    def remove(self, element):
        script = "arguments[0].parentNode.removeChild(arguments[0]);"
        self.execute_script(script, element)


    def get_scroll_x(self):
        return self.execute_script(
            "return document.documentElement.scrollLeft || document.body.scrollLeft;")


    def get_scroll_y(self):
        return self.execute_script(
            "return document.documentElement.scrollTop || document.body.scrollTop;")


    def element_text(self, element):
        """
        Text of element not including children
        """

        return self.execute_script("""
return jQuery(arguments[0]).contents().filter(function() {
    return this.nodeType == Node.TEXT_NODE;
}).text();
""", element)


    def keep(self, timeout):
        interval = 0.5
        expired = 0

        while True:
            if expired >= timeout:
                break
            for item in self.get_log('driver'):
                if "disconnected" in item["message"]:
                    break
            else:
                time.sleep(interval)
                expired += interval
                continue
            break


    def clear_js_error_url(self, url, status_code):
        """
        Assert that there exists a console error matching `url` and `status_code`.
        Remove the error from the JS log buffer.
        """

        return self.clear_js_error(
            level="SEVERE", source="network", message=[
                url,
                str(status_code)
            ])


    def clear_js_error(
            self,
            level: Union[str, None] = None,
            source: Union[str, None] = None,
            message: Union[Iterable[str], str, None] = None,
            wait: Union[int, None] = 1,
    ):
        """
        `message`: if a list, error messages must contain all strings in list.
        """

        error = None
        message_ = []
        if message:
            if isinstance(message, str):
                message_ = [message]
            elif isinstance(message, Iterable):
                message_ = message

        interval = 0.5
        while wait >= 0:
            self.js_log_flush_to_buffer()
            i = None
            for i, entry in enumerate(self.js_log_iterate_buffer()):
                if level is not None and entry["level"] != level:
                    continue
                if source is not None and entry["source"] != source:
                    continue

                for item in message_:
                    if item not in entry["message"]:
                        break
                else:
                    error = entry
                    break

            if error:
                break

            time.sleep(interval)
            wait -= interval

        if not error:
            LOG.error("JS Log:")
            for entry in self.js_log_iterate_buffer():
                LOG.error("  %s", repr(entry))

        assert error, f"No Javascript errors with message matching {repr(message_)}."

        self._js_log_buffer.pop(i)

        return error


    def js_log_flush_to_buffer(self):
        # This removes read from the Selenium driver log.
        self._js_log_buffer += list(self.get_log("browser"))


    def js_log_iterate_buffer(self):
        self.js_log_flush_to_buffer()
        for item in self._js_log_buffer:
            yield item


    def js_log_buffer_length(self):
        self.js_log_flush_to_buffer()
        return len(self._js_log_buffer)


    def js_log_empty_buffer(self):
        self._js_log_buffer.clear()


    def js_log_filter_buffer(self, f):
        self.js_log_flush_to_buffer()
        self._js_log_buffer = [v for v in self._js_log_buffer if f(v)]


    def javascript_log(self):
        def format_message(text):
            return text.split(" ", 2)[2]

        return [
            format_message(v["message"])
            for v in self.js_log_iterate_buffer()
            if v["source"] == "console-api"
        ]


    def javascript_errors(
            self,
            host: Union[Iterable[str], str, None] = None,
            ignore: Union[Iterable[str], str, None] = None,
            allow_warnings: Union[bool, None] = None
    ):
        host_list = [host] if isinstance(host, str) else host
        ignore_set = (
            set(ignore) if isinstance(ignore, (set, list, dict)) else
            set([ignore]) if ignore else
            set())


        def is_ignored(entry):
            if entry["source"] == "console-api":
                return True

            for item in ignore_set:
                if isinstance(item, re.Pattern):
                    if bool(item.search(entry["message"])):
                        return True
                else:
                    if item in entry["message"]:
                        return True
            return False


        errors = []
        for entry in self.js_log_iterate_buffer():
            if is_ignored(entry):
                continue

            if entry["level"] == "SEVERE":
                if entry["source"] == "network" and "http" in entry["message"]:
                    for host_item in host_list or []:
                        if host_item in entry["message"]:
                            break
                    else:
                        continue

            if entry["level"] == "WARNING" and allow_warnings:
                continue

            errors.append(entry)

        return errors


    def wait_until(self, f, wait=None):
        if wait is None:
            wait = self._default_timeout
        if wait is False:
            wait = 0
        return WebDriverWait(self, wait).until(f)
