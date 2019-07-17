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
import time

import requests

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.support.wait import WebDriverWait
from selenium.common.exceptions import \
    NoSuchElementException, NoSuchWindowException, WebDriverException



DEFAULT_CHROMEDRIVER_PATH = "/usr/lib/chromium-browser/chromedriver"
DEFAULT_TIMEOUT = 15



class WindowGeometry():
    def __init__(self, text):
        pattern = r"^([1-9][0-9]*)x([1-9][0-9]*)\+([0-9]+)\+([0-9]+)"

        match = re.compile(pattern).match(text.strip())
        if not match:
            raise ValueError(f"Could not parse window geometry string {text})")

        (self.width, self.height, self.x, self.y) = [int(v) for v in match.groups()]



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

        if show:
            chrome_options.add_argument('--auto-open-devtools-for-tabs')
        else:
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


    def find(
            self, selector,
            node=None, method="css", multiple=False, wait=None, required=False
    ):
        if wait in (None, True):
            wait = self._default_timeout

        if wait is False:
            wait = 0

        if node is None:
            node = self._driver

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

        if required:
            assert result

        return result


    def find_all(self, *args, **kwargs):
        return self.find(multiple=True, *args, **kwargs)


    def scroll_to_view(self, element):
        ActionChains(self).move_to_element(element).perform()


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


    def javascript_errors(self, base_url):
        errors = []
        for entry in self.get_log("browser"):
            if entry["level"] == "SEVERE" and entry["source"] == "network":
                if "http" in entry["message"] and base_url not in entry["message"]:
                    continue

            errors.append(entry)

        return errors


    def wait_until(self, f, wait=None):
        if wait is None:
            wait = self._default_timeout
        if wait is False:
            wait = 0
        return WebDriverWait(self, wait).until(f)
