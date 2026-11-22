#!/usr/bin/env python3
"""Builds src/main/data/kb.json (the AI reviewer's knowledge base) and webchecklist.json.

Usage: build-knowledge.py <knowledge-base folder> <checklist .txt from the docx>
The knowledge base is written in our own words. The raw report corpus ("training", "imported") is left out on purpose.
"""
import json, os, re, sys
kb, checklist = sys.argv[1], sys.argv[2]
DIRS = ['logic','authz','authn','web','api','mobile','client-side','files-and-ssrf','payments','fintech','injection','server-side','cloud','js-analysis','recon-notes','advanced','ai','rules']
trig = {}
for line in open(os.path.join(kb, 'INDEX.md'), encoding='utf8'):
    m = re.match(r'^- (.*?):\s*`([^`]+\.md)`', line)
    if m: trig[m.group(2)] = m.group(1).strip()
files = []
for d in DIRS:
    base = os.path.join(kb, d)
    if not os.path.isdir(base): continue
    for name in sorted(os.listdir(base)):
        if not name.endswith('.md'): continue
        rel = f'{d}/{name}'
        text = open(os.path.join(base, name), encoding='utf8').read().replace('—', ':').replace('–', '-')
        title = (re.search(r'^# (.+)$', text, re.M) or [None, name[:-3]])[1].strip()
        files.append({'id': rel[:-3], 'title': title, 'trigger': trig.get(rel, ''), 'text': text.strip()})
out = os.path.join(os.path.dirname(__file__), '..', 'src', 'main', 'data')
json.dump({'files': files}, open(os.path.join(out, 'kb.json'), 'w'), ensure_ascii=False, separators=(',', ':'))
print('knowledge files:', len(files), 'bytes:', os.path.getsize(os.path.join(out, 'kb.json')))

lines = open(checklist, encoding='utf8').read().split('\n')
start = [i for i, l in enumerate(lines) if l.strip() == 'Web Application Security Checklist'][0]
toc = [re.sub(r'^\d+\.\s*', '', l.strip()) for l in lines[:start] if re.match(r'^\d+\. ', l.strip())]
norm = lambda s: re.sub(r'[^a-z0-9]+', ' ', s.lower()).strip()
want = [norm(t) for t in toc]
sections, cur = [], None
for l in lines[start + 1:]:
    s = l.strip()
    if not s: continue
    if s.startswith('-'):
        if cur is not None: cur['items'].append(re.sub(r'^-\s*(\[ \]\s*)?', '', s).replace('—', ':').replace('–', '-'))
        continue
    # Every line that is not a bullet is the next section's heading (the contents page spells some differently).
    cur = {'n': len(sections) + 1, 'title': s.replace('\u2013', '-'), 'items': []}
    sections.append(cur)
assert len(sections) == len(toc), (len(sections), len(toc))
json.dump({'sections': sections}, open(os.path.join(out, 'webchecklist.json'), 'w'), ensure_ascii=False, indent=0)
print('sections:', len(sections), 'items:', sum(len(s['items']) for s in sections))
print([ (s['n'], len(s['items'])) for s in sections])
