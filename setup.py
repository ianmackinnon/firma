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

from pathlib import Path

import setuptools

PACKAGE_PATH = Path(__file__).parent.resolve()

exec((PACKAGE_PATH / "firma" / "version.py").read_text())

README = (PACKAGE_PATH / "README.md").read_text()
DESC = README.split("\n\n")[1]


setuptools.setup(
    name="firma",
    version=__version__,
    author="Ian Mackinnon",
    author_email="imackinnon@gmail.com",
    description=DESC,
    long_description=README,
    long_description_content_type="text/markdown",
    url="https://github.com/ianmackinnon/firma",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    install_requires=[
        "jsonschema",
        "humanize",
        "onetimepass",
        "pymysql",
        "pytest",
        "python-dateutil",
        "redis",
        "requests",
        "selenium",
        "sqlalchemy",
        "sqlparse",
        "tornado",
        "unidecode",
    ],
    python_requires='>=3',
    scripts=[
        "scripts/firma-mysql",
    ],
    setup_requires=[],
    tests_require=[],
    include_package_data=True,
)
