import re
import httpx

r = httpx.get('https://data.mendeley.com/datasets/mzn9hvdcxg/2', headers={'User-Agent': 'Mozilla/5.0'})
text = r.text

print("=== Found Links ===")
links = re.findall(r'<a\s+[^>]*href="([^"]+)"[^>]*>(.*?)</a>', text, re.DOTALL)
for href, inner in links:
    clean_inner = re.sub(r'<[^>]+>', '', inner).strip()
    if any(k in href.lower() or k in clean_inner.lower() for k in ['download', 'file', 'csv', 'zip', 'mzn', 'data']):
        print(f"Text: '{clean_inner}' -> Href: '{href}'")

print("\n=== Found Buttons ===")
buttons = re.findall(r'<button\s*([^>]*)>(.*?)</button>', text, re.DOTALL)
for attrs, inner in buttons:
    clean_inner = re.sub(r'<[^>]+>', '', inner).strip()
    print(f"Button: '{clean_inner}' | Attrs: '{attrs[:100]}'")
