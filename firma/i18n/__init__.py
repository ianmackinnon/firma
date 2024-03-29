import re
import logging
from collections import defaultdict



LOG = logging.getLogger('firma.i18n')



def msgkey(msg):
    if not "msgid" in msg:
        return None

    key = msg["msgid"]
    if ctxt := msg.get("msgctxt", None):
        key = ctxt + "\u0004" + key
    return key



def get_source_lang(po_in):
    for line in list(po_in.read_text().splitlines()):
        if match := re.search(r"\bLanguage:\s*([a-z]+)", line):
            return match.group(1)

    return None



def iterate_po(path):
    msg = {}
    field = None

    for line in list(path.read_text().splitlines()):
        if match := re.match(r"(msgid|msgctxt|msgstr) \"(.*)\"$", line):
            field, text = match.groups()
            if field != "msgstr" and msg and "msgstr" in msg:
                yield msg
                msg = {}

            msg[field] = text
            continue

        if match := re.match(r"\"(.*)\"$", line):
            text = match.group(1)
            assert field
            assert field in msg
            msg[field] += text
            continue

        if match := re.match(r"(#.*)?$", line):
            if msg:
                yield msg
            msg = {}
            field = None

            yield {
                "comment": match.group(0)
            }
            continue

        raise Exception("Unexpected line: %s" % repr(line))

    if msg:
        yield msg



def podict(path):
    return {msgkey(msg): msg for msg in iterate_po(path) if msgkey(msg)}



def format_unpo(text):
    text = re.sub(r"\n", "", text)
    text = re.sub(r"\\n", "\n", text)
    return text



def format_mask_tokens(text, d):
    def sub(match):
        whole = match.group(0)
        key = "%d" % len(d)
        value = match.group(1)

        d[key] = value

        return whole.replace(value, key)

    text = re.sub(r"<{(.*?)}>", sub, text)
    text = re.sub(r"\]\((.*?)\)", sub, text)

    return text, d



def format_restore_tokens(text, d):
    def sub(match):
        whole = match.group(0)
        key = match.group(1)
        value = d[key]

        print("unmask:", key, value, whole)

        return whole.replace(key, value)

    text = re.sub(r"<{(.*?)}>", sub, text)
    text = re.sub(r"\]\((.*?)\)", sub, text)

    return text



def translate_po(
        out, po_in, target, translate_item,
        target_dict=None, protect=None, missing_only=None,
):
    stats = defaultdict(int)

    def write_msg(msg):
        assert set(msg.keys()) >= {"msgid", "msgstr"}

        for key in ["msgctxt", "msgid", "msgstr"]:
            if (value := msg.get(key, None)) is not None:
                if "\n" in value:
                    # Don't remove trailing spaces from single lines, eg. ` and `
                    value = value.rstrip()

                for i, line in enumerate(value.split("\n")):
                    if i == 0:
                        out.write("%s " % key)
                    out.write("\"%s\"\n" % line)


    source = get_source_lang(po_in)

    assert source


    for msg in iterate_po(po_in):

        if "comment" in msg:
            out.write("%s\n" % msg["comment"])
            stats["comment"] += 1
            continue

        msg["msgstr"] = msg["msgstr"].replace(
            f"Language: {source}",
            f"Language: {target}"
        )

        if not msg["msgid"]:
            write_msg(msg)
            stats["header"] += 1
            continue

        if target_dict is not None:
            key = msgkey(msg)
            if msg2 := target_dict.get(key, None):
                if missing_only:
                    stats["existing"] += 1
                    write_msg(msg2)
                    continue

                if (
                        protect and
                        msg.get("msgctxt", None) and
                        protect.search(msg["msgctxt"])
                ):
                    stats["protected"] += 1
                    write_msg(msg2)
                    continue

        msg["msgstr"] = translate_item(msg["msgstr"], stats=stats)
        stats["translated"] += 1
        write_msg(msg)

    return stats
