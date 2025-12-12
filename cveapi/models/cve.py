from datetime import datetime
from dataclasses import dataclass
from typing import List
import logging

from .cvss import CVSSMetric, CVSSv2Metric, CVSSv3Metric, CVSSv4Metric


logger = logging.getLogger(__name__)

@dataclass
class CVEReference:
    url: str
    source: str
    tags: List[str]

    def __str__(self):
        return f"{self.url} (Source: {self.source}, Tags: {', '.join(self.tags)})"


class CVE:

    id: str
    sourceIdentifier: str
    published: datetime
    lastModified: datetime
    vulnStatus: str
    description: str
    metrics: dict
    references: List[CVEReference]


    def __init__(self, cve_data: dict, lang:str = 'en'):
        self.id = cve_data['id']
        self.sourceIdentifier = cve_data['sourceIdentifier']
        self.published = datetime.fromisoformat(cve_data['published'])
        self.lastModified = datetime.fromisoformat(cve_data['lastModified'])
        self.vulnStatus = cve_data['vulnStatus']
        self.description = [desc['value'] for desc in cve_data.get('descriptions', []) if desc['lang'] == lang][0]
        self.metrics = self._parse_metrics(cve_data.get('metrics', {}))
        self.references = self._parse_references(cve_data.get('references', []))
        
    def _parse_references(self, references: list[dict]):
        """
        Parses CVE's various references.
        """
        parsed_refs = []
        for ref in references:
            try:
                parsed_refs.append(
                    CVEReference(
                        url=ref['url'],
                        source=ref.get('source', ''),
                        tags=ref.get('tags', [])
                    )
                )
            except KeyError as e:
                logger.warning("CVE %s Parsing Error: %s", self.id, e)
        return parsed_refs


    def _parse_metrics(self, metrics: dict) -> dict[str, CVSSMetric]:
        """
        Parses CVE's various CVSS metrics.
        """
        parsed_metrics = {}
        for metric in metrics.values():
            metric = metric[0]
            match metric['cvssData']['version']:
                case '3.0' | '3.1':
                    parsed_metrics['3'] = CVSSv3Metric(metric)
                case '2.0':
                    parsed_metrics['2'] = CVSSv2Metric(metric)
                case '4.0':
                    parsed_metrics['4'] = CVSSv4Metric(metric)
        return parsed_metrics
    
    def __repr__(self):
        return f"<{self.id}>"
    
    def __str__(self):
        pubtime = self.published.strftime('%I%p %d/%m/%Y').lstrip('0')
        lastmodtime = self.lastModified.strftime('%I%p %d/%m/%Y').lstrip('0')
        
        return f"CVE ID: {self.id}\nPublished: {pubtime}\nLast Modified: {lastmodtime}\nStatus: {self.vulnStatus}\nDescription: {self.description}" 