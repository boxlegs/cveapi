import requests
from datetime import datetime

class CVE:

    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: str
    descriptions: str
    metrics: dict
    references: list[dict]


    def __init__(self, cve_data, lang='en'):
        self.id = cve_data['id']
        self.sourceIdentifier = cve_data['sourceIdentifier']
        self.published = datetime.fromisoformat(cve_data['published'])
        self.lastModified = datetime.fromisoformat(cve_data['lastModified'])
        self.vulnStatus = cve_data['vulnStatus']
        self.descriptions = [desc['value'] for desc in cve_data.get('descriptions', []) if desc['lang'] == lang][0]
        self.metrics = cve_data.get('metrics', {})
        self.references = cve_data.get('references', [])

    def __repr__(self):
        return f"<CVE {self.id}>"
    
    def __str__(self):
        pubtime = self.published.strftime('%I%p %d/%m/%Y').lstrip('0')
        lastmodtime = self.lastModified.strftime('%I%p %d/%m/%Y').lstrip('0')
        
        return f"CVE ID: {self.id}\nPublished: {pubtime}\nLast Modified: {lastmodtime}\nStatus: {self.vulnStatus}\nDescriptions: {self.descriptions}" 


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


