import html.parser
import urllib.request


class LinkParser(html.parser.HTMLParser):

  def __init__(self):
    super().__init__()
    self.current_tag = ""
    self.current_attrs = {}
    self.current_text = []

  def handle_starttag(self, tag, attrs):
    self.current_tag = tag
    self.current_attrs = dict(attrs)
    self.current_text = []

  def handle_data(self, data):
    self.current_text.append(data.strip())

  def handle_endtag(self, tag):
    text = " ".join(t for t in self.current_text if t)
    if tag == "a" and "href" in self.current_attrs:
      print(f"A: [{text}] -> {self.current_attrs['href']}")
    elif tag in ("button", "form", "input"):
      print(f"{tag.upper()}: [{text}] -> {self.current_attrs}")


url = "https://cspectrum.web.cse.unsw.edu.au"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=15) as resp:
  html_data = resp.read().decode("utf-8", errors="ignore")

parser = LinkParser()
parser.feed(html_data)
