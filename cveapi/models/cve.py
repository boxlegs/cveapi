from datetime import datetime
from typing import List

from .cvss import CVSSv2Metric, CVSSv3Metric, CVSSv4Metric

class CVE:

    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: str
    description: str
    metrics: dict
    references: list[dict]


    def __init__(self, cve_data, lang='en'):
        self.id = cve_data['id']
        self.sourceIdentifier = cve_data['sourceIdentifier']
        self.published = datetime.fromisoformat(cve_data['published'])
        self.lastModified = datetime.fromisoformat(cve_data['lastModified'])
        self.vulnStatus = cve_data['vulnStatus']
        self.description = [desc['value'] for desc in cve_data.get('descriptions', []) if desc['lang'] == lang][0]
        self.metrics = self._parse_metrics(cve_data.get('metrics', {}))
        self.references = cve_data.get('references', [])

    def _parse_metrics(self, metrics):
        parsed_metrics = {}
        for metric in metrics.values():
            metric = metric[0]
            match metric['cvssData']['version']:
                case '3.0' | '3.1':
                    parsed_metrics['3'] = CVSSv3Metric(metric)
                case '2.0':
                    pass
                    parsed_metrics['2'] = CVSSv2Metric(metric)
                case '4.0':
                    parsed_metrics['4'] = CVSSv4Metric(metric)
                    pass
        return parsed_metrics
    
    def __repr__(self):
        return f"<{self.id}>"
    
    def __str__(self):
        pubtime = self.published.strftime('%I%p %d/%m/%Y').lstrip('0')
        lastmodtime = self.lastModified.strftime('%I%p %d/%m/%Y').lstrip('0')
        
        return f"CVE ID: {self.id}\nPublished: {pubtime}\nLast Modified: {lastmodtime}\nStatus: {self.vulnStatus}\nDescription: {self.description}" 
