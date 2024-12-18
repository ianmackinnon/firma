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



import logging
from pathlib import Path
from tempfile import NamedTemporaryFile
from subprocess import Popen, PIPE



LOG = logging.getLogger("firma.pdf")



def mm2pt(mm):
    return mm * 72 / 25.4



def run(command):
    LOG.debug(" ".join(command))

    # Since 2024-12 this fails for Ghostscript commands when not in shell mode.
    proc = Popen(" ".join(command), stdout=PIPE, stderr=PIPE, shell=True)
    (out, err) = proc.communicate()
    if out:
        LOG.debug("stdout: %s", out.decode("utf8"))
    if err:
        LOG.error("stderr: %s", err.decode("utf8"))
    if proc.returncode:
        LOG.error("return code: %d", proc.returncode)

        LOG.error(" ".join(command))
        raise Exception("PDF command failed.")



def temp_path(prefix=None, suffix=None):
    return Path(NamedTemporaryFile(
        prefix=prefix, suffix=suffix, delete=False).name)



def write_compressed_pdf(out_path, in_path):
    command = [
        "gs",
        "-o", str(out_path),
        "-dQUIET",
        "-dNOPAUSE",
        "-dBATCH",
        "-sDEVICE=pdfwrite",
        "-dDownsampleColorImages=true",
        "-dDownsampleGrayImages=true",
        "-dDownsampleMonoImages=true",
        "-dColorImageResolution=72",
        "-dGrayImageResolution=72",
        "-dMonoImageResolution=72",
        "-dColorImageDownsampleThreshold=1.0",
        "-dGrayImageDownsampleThreshold=1.0",
        "-dMonoImageDownsampleThreshold=1.0",
        "-f", str(in_path),
    ]

    run(command)



def write_header_pdf(out_path, headers):
    top = 2
    left = 2
    font_size = 2.5
    line_height = 4
    page_height = 297

    gs_command = [
        "/Courier findfont",
        f"{mm2pt(font_size)} scalefont",
        "setfont",
    ]

    for header in headers:
        gs_command += [
            f"{mm2pt(left)} {mm2pt(page_height - top - font_size)} moveto",
            f"({header}) show",
        ]
        top += line_height

    gs_command += [
        "showpage",
    ]

    gs_command_string = ' '.join(gs_command)

    command = [
        "gs",
        "-o", str(out_path),
        "-dQUIET",
        "-dBATCH",
        "-dNOPAUSE",
        "-sDEVICE=pdfwrite",
        "-c", '"%s"' % gs_command_string
    ]

    run(command)



def write_headed_pdf(out_path, in_path_1, in_path_2):
    command = [
        "pdftk",
        str(in_path_1),
        "stamp",
        str(in_path_2),
        "output",
        str(out_path),
    ]

    run(command)



def write_combined_pdf(out_path, *in_path_list):
    command = [
        "pdftk",
    ] + [str(v) for v in in_path_list] + [
        "cat",
        "output",
        str(out_path),
    ]

    run(command)
