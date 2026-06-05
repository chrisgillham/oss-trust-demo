import urllib.request, json
data = json.dumps({'version':'2.32.3','package':{'name':'requests','ecosystem':'PyPI'}}).encode()
req = urllib.request.Request('https://api.osv.dev/v1/query', data=data, headers={'Content-Type':'application/json'})
resp = urllib.request.urlopen(req)
result = json.loads(resp.read())
vulns = result.get('vulns', [])
print('Vulnerabilities found:', len(vulns))
for v in vulns:
    print(' ', v['id'], '-', v.get('summary', 'no summary'))
