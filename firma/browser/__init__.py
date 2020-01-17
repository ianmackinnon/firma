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
from selenium.webdriver.support.wait import WebDriverWait
from selenium.common.exceptions import \
    NoSuchElementException, NoSuchWindowException, WebDriverException

from firma.pdf import write_compressed_pdf, write_header_pdf, write_headed_pdf, temp_path



LOG = logging.getLogger("firma.browser")

DEFAULT_CHROMEDRIVER_PATH = "/usr/lib/chromium-browser/chromedriver"
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
            show=None, geometry=None, socks5_proxy=None
    ):

        if chromedriver_path is None:
            chromedriver_path = DEFAULT_CHROMEDRIVER_PATH

        chrome_options = Options()

        chrome_options.add_argument('--auto-open-devtools-for-tabs')
        if not show:
            chrome_options.add_argument("--headless")

        if socks5_proxy:
            chrome_options.add_argument(f"--proxy-server=socks5://{socks5_proxy}")


        driver = webdriver.Chrome(
            options=chrome_options,
            executable_path=chromedriver_path,
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

        return driver



    def __init__(
            self,
            driver=None,
            default_timeout=None,
            chromedriver_path=None,
            show=None,
            geometry=None,
            socks5_proxy=None
    ):


        if default_timeout is None:
            default_timeout = DEFAULT_TIMEOUT

        if driver is None:
            driver = SeleniumDriver.get_driver(
                chromedriver_path,
                show=show, geometry=geometry, socks5_proxy=socks5_proxy
            )

        self._driver = driver

        self._default_timeout = default_timeout
        self.set_and_verify_implicit_timeout(self._default_timeout)


    def close_if_open(self):
        try:
            self._driver.close()
        except (WebDriverException, NoSuchWindowException):
            pass


    def __getattr__(self, name):
        if name == "switch_to" and self._show:
            LOG.warning("Warning: Switching to an iframe is unstable when browser is visible.")
        return getattr(self._driver, name)


    def get_timeout(self, key):
        """
        `key` should be one of 'implicit', 'pageLoad', 'script'.

        Timeout is:
        -   Returned from here in seconds
        -   Given by Selenium API in milliseconds
        -   Set by Selenium-Python in seconds
        """

        result = requests.get(
            f"{self.command_executor._url}"
            f"/session/{self.session_id}/timeouts"
        )

        timeouts = result.json()
        return timeouts["value"][key] / 1000


    def set_and_verify_implicit_timeout(self, timeout):
        assert self.get_timeout("implicit") == 0
        self.implicitly_wait(timeout)
        assert self.get_timeout("implicit") == timeout

    def send_command(self, cmd, params=None):
        url = (
            f"{self.command_executor._url}"
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
                    f"`{selector}`"
                    "Did you mean to search for `descendant::`?")

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


    def scroll_and_click(self, element):
        LOG.debug("Scrolling to link for %s...", element.text)
        self.scroll_to_center(element)
        LOG.debug("Done")

        LOG.debug("Clicking link for %s...", element.text)
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
        interval = 0.1
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


    def assert_failed(self, url, status_code):
        """
        Assert that there exists a console error matching `url` and `status_code`.
        """

        fail_message = None
        for entry in self.get_log("browser"):
            if (
                    entry["level"] == "SEVERE" and
                    entry["source"] == "network" and
                    url in entry["message"] and
                    str(status_code) in entry["message"]
            ):
                fail_message = entry
                break
        assert fail_message


    def javascript_errors(
            self,
            host: Union[Iterable[str], str, None] = None,
            host_ignore: Union[Iterable[str], str, None] = None,
            allow_warnings: Union[bool, None] = None
    ):
        host_list = [host] if isinstance(host, str) else host
        host_ignore_list = [host_ignore] if isinstance(host_ignore, str) else host_ignore

        def ignore(entry):
            for third_party in host_ignore_list or []:
                if third_party in entry["message"]:
                    return True
            return False

        errors = []
        for entry in self.get_log("browser"):
            if ignore(entry):
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
