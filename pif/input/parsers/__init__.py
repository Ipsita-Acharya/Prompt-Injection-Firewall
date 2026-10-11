"""Parser registry (Phase 2): format name -> parser instance.

The registry mirrors the identify() output kinds; adding a new format means
adding a parser module with the common Parser interface and one entry here."""

from pif.input.parsers.docx import DocxParser
from pif.input.parsers.email import EmailParser
from pif.input.parsers.html import HtmlParser
from pif.input.parsers.image import ImageParser
from pif.input.parsers.json import JsonParser
from pif.input.parsers.markdown import MarkdownParser
from pif.input.parsers.pdf import PdfParser
from pif.input.parsers.text import TextParser

PARSERS = {
    "pdf": PdfParser(),
    "docx": DocxParser(),
    "email": EmailParser(),
    "image": ImageParser(),
    "html": HtmlParser(),
    "json": JsonParser(),
    "markdown": MarkdownParser(),
    "text": TextParser(),
}
