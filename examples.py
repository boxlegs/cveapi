import cveapi


[print(cvss) for cvss in cveapi.get_cve_by_id('CVE-2025-55182').metrics.values()]