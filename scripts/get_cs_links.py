import re
import urllib.request

url = "https://cspectrum.web.cse.unsw.edu.au"
req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
with urllib.request.urlopen(req, timeout=15) as resp:
    html = resp.read().decode("utf-8", errors="ignore")

print("HTML size:", len(html))
links = re.findall(r'href=["\']([^"\']+)["\']', html)
for l in links:
    if any(k in l.lower() for k in ["zip", "download", "pcap", "dataset", "mix", "aes", "chacha"]):
        print("Link:", l)
