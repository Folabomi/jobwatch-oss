#!/usr/bin/env python3
"""Read and rewrite a .docx by moving whole paragraphs, never rebuilding them.

This is the file that makes "never invent a fact" structural rather than a
promise. A tailored CV is assembled by selecting and reordering paragraph blocks
lifted byte for byte out of the source, so a claim can only appear in the output
if it already existed in the input. Two lines are exempt and rewritten from a
whitelist: the subtext line and the core competencies line.

Everything here is stdlib. A .docx is a zip of XML, and the paragraphs live in
word/document.xml as <w:p> ... </w:p> blocks. Moving those blocks preserves the
runs, fonts, numbering and spacing exactly, which is why the output opens in
Word looking like the original.
"""

import re
import shutil
import zipfile

DOC_PART = "word/document.xml"
APP_PART = "docProps/app.xml"

PARA_RE = re.compile(r"<w:p[ >].*?</w:p>", re.S)
TEXT_RE = re.compile(r"<w:t[^>]*>(.*?)</w:t>", re.S)
STYLE_RE = re.compile(r'w:pStyle w:val="([^"]+)"')

ENTITIES = (("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&apos;", "'"))


def unescape(text):
    for entity, char in ENTITIES:
        text = text.replace(entity, char)
    return text


def escape(text):
    out = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return out


def para_text(block):
    """The visible text of one paragraph."""
    return unescape(re.sub(r"\s+", " ", "".join(TEXT_RE.findall(block))).strip())


def is_bullet(block):
    style = STYLE_RE.search(block)
    return bool(style and style.group(1) == "ListParagraph")


def is_heading(block):
    """Headings are ALL CAPS paragraphs. The variants use no heading styles, so
    case is the only signal, and it is a consistent one across all five."""
    text = para_text(block)
    if not (3 < len(text) < 70) or is_bullet(block):
        return False
    letters = [c for c in text if c.isalpha()]
    return bool(letters) and all(c.isupper() for c in letters)


class Document(object):
    def __init__(self, path):
        self.path = path
        with zipfile.ZipFile(path) as archive:
            self.names = archive.namelist()
            self.parts = {name: archive.read(name) for name in self.names}
        self.xml = self.parts[DOC_PART].decode("utf-8")
        self.head, self.blocks, self.tail = self._split()

    def _split(self):
        matches = list(PARA_RE.finditer(self.xml))
        if not matches:
            raise ValueError("no paragraphs in {}".format(self.path))
        head = self.xml[: matches[0].start()]
        tail = self.xml[matches[-1].end():]
        return head, [m.group(0) for m in matches], tail

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def texts(self):
        return [para_text(b) for b in self.blocks]

    def word_count(self):
        return sum(len(para_text(b).split()) for b in self.blocks)

    def sections(self):
        """Group blocks under their most recent ALL-CAPS heading.

        Returns a list of (heading_index, [member_indexes]). The blocks before
        the first heading are the name and contact block and belong to nobody.
        """
        groups = []
        current = None
        for index, block in enumerate(self.blocks):
            if is_heading(block):
                current = (index, [])
                groups.append(current)
            elif current is not None:
                current[1].append(index)
        return groups

    def find(self, needle):
        """Index of the first paragraph containing needle, or None."""
        low = needle.lower()
        for index, block in enumerate(self.blocks):
            if low in para_text(block).lower():
                return index
        return None

    # ------------------------------------------------------------------
    # Writing
    # ------------------------------------------------------------------

    def set_text(self, index, new_text):
        """Replace the visible text of one paragraph, keeping its formatting.

        Only ever used on the two whitelisted lines. It writes the new string
        into the first run and empties the rest, so the paragraph keeps its own
        style and the change is confined to characters.
        """
        block = self.blocks[index]
        runs = list(re.finditer(r"(<w:t[^>]*>)(.*?)(</w:t>)", block, re.S))
        if not runs:
            raise ValueError("paragraph {} has no text runs".format(index))
        out, last = [], 0
        for position, run in enumerate(runs):
            out.append(block[last:run.start()])
            replacement = escape(new_text) if position == 0 else ""
            opening = run.group(1)
            if position == 0 and "xml:space" not in opening:
                opening = opening[:-1] + ' xml:space="preserve">'
            out.append(opening + replacement + run.group(3))
            last = run.end()
        out.append(block[last:])
        self.blocks[index] = "".join(out)

    def insert_after(self, index, text, template=None):
        """Add a paragraph by cloning an existing one and replacing its words.

        Cloning rather than authoring the XML keeps the numbering, indent and run
        properties identical to the paragraph it sits beside, which is why the
        result opens in Word looking like it was always there. New text is the
        one thing this file allows to be new, so it is only ever used for source
        material the author wrote.
        """
        source = self.blocks[template if template is not None else index]
        self.blocks.insert(index + 1, source)
        self.set_text(index + 1, text)
        return index + 1

    def _stale_page_count(self):
        """Blank Word's cached page and word counts on the way out.

        They describe the document before the edit, and a wrong number is worse
        than no number: a later check would read two pages off a file that is
        three. Word recomputes both the moment it opens the file.
        """
        if APP_PART not in self.parts:
            return
        text = self.parts[APP_PART].decode("utf-8")
        for tag in ("Pages", "Words", "Characters", "Lines", "Paragraphs"):
            text = re.sub(r"<{0}>\d+</{0}>".format(tag), "", text)
        self.parts[APP_PART] = text.encode("utf-8")

    def keep(self, indexes):
        """Reduce the document to these paragraph indexes, in this order."""
        self.blocks = [self.blocks[i] for i in indexes]

    def save(self, out_path):
        """Write a new docx. Every part except document.xml is copied verbatim,
        so headers, footers, styles and numbering are untouched."""
        xml = self.head + "".join(self.blocks) + self.tail
        self._stale_page_count()
        shutil.copyfile(self.path, out_path)
        # A zip cannot have an entry rewritten in place, so rebuild it in order.
        with zipfile.ZipFile(self.path) as source:
            infos = source.infolist()
        with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED) as target:
            for info in infos:
                data = xml.encode("utf-8") if info.filename == DOC_PART else self.parts[info.filename]
                target.writestr(info, data)
        return out_path


def page_count(path):
    """Pages as Word last computed them, or None if it has never saved this file.

    Word stamps docProps/app.xml on save, which is the only real page number
    available without a renderer. It was worth finding: a variant believed to be
    two pages measured three, and the tailored copy sent to a real application
    measured three as well.
    """
    with zipfile.ZipFile(path) as archive:
        if APP_PART not in archive.namelist():
            return None
        found = re.search(r"<Pages>(\d+)</Pages>", archive.read(APP_PART).decode("utf-8"))
    return int(found.group(1)) if found else None


def extract_text(path):
    """What a parser sees. This is the ATS check for a .docx: read the XML and
    take the text, which is exactly what a resume parser does with this format."""
    return [para_text(b) for b in Document(path).blocks if para_text(b)]
