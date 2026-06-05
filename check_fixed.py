import urllib.request, json

for ghsa in ['GHSA-9hjg-9r4m-mvj7', 'GHSA-gc5v-m9x4-r6x2']:
    url = f'https://api.osv.dev/v1/vulns/{ghsa}'
    resp = urllib.request.urlopen(url)
    data = json.loads(resp.read())
    print('Advisory:', ghsa)
    for affected in data.get('affected', []):
        for r in affected.get('ranges', []):
            for ev in r.get('events', []):
                if 'fixed' in ev:
                    print('  Fixed in:', ev['fixed'])
    print()
