import re
import urllib.request

url = "https://cspectrum.web.cse.unsw.edu.au/cipherspectrum/"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=15) as resp:
  html = resp.read().decode("utf-8", errors="ignore")

for m in re.finditer(
    r'<a href="([^"?][^"]*)">([^<]*)</a>\s*</td><td align="right">([^<]*)</td><td align="right">\s*([0-9\.]+[KMG]?)',
    html,
):
  print(f"File: {m.group(1):<30} Size: {m.group(4):<10} Date: {m.group(3)}")
