import cveapi

print(cveapi.get_cve_by_id('CVE-2017-0150').metrics)