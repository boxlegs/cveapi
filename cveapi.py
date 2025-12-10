import requests
from models import CVE
        
    
def call_nvd_api(parameters):
    return requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params=parameters)

def get_cve_by_id(cve_id):
    req = call_nvd_api({'cveId': cve_id})
    if req.status_code == 200:
        return CVE(req.json().get('vulnerabilities')[0].get('cve'))
    
def get_cves_by_tag(cve_tag):
    req = call_nvd_api({'cveTag': cve_tag})
    if req.status_code == 200:
        return req.json()


