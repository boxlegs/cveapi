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
                    # parsed_metrics['4'] = CVSSv4Metric(metric)
                    pass
        return parsed_metrics
    
    def __repr__(self):
        return f"<CVE {self.id}>"
    
    def __str__(self):
        pubtime = self.published.strftime('%I%p %d/%m/%Y').lstrip('0')
        lastmodtime = self.lastModified.strftime('%I%p %d/%m/%Y').lstrip('0')
        
        return f"CVE ID: {self.id}\nPublished: {pubtime}\nLast Modified: {lastmodtime}\nStatus: {self.vulnStatus}\nDescriptions: {self.descriptions}" 

"""
Abstract class for CVSS Metrics
"""
class CVSSMetric:
    
    source: str
    type: str
    version: str
    baseScore: str
    baseSeverity: str
    exploitabilityScore: str
    impactScore: str

    # Impact Metrics
    confidentialityImpact: str
    integrityImpact: str
    availabilityImpact: str
    
    def __init__(self, data):
        self.source = data['source']
        self.type = data['type']
        self.version = data['cvssData']['version']
        self.baseScore = data['cvssData']['baseScore']
        self.exploitabilityScore = data['exploitabilityScore']
        self.impactScore = data['impactScore']
        self.confidentialityImpact = data['cvssData']['confidentialityImpact']
        self.integrityImpact = data['cvssData']['integrityImpact']
        self.availabilityImpact = data['cvssData']['availabilityImpact']

    def vectorString(self):
        pass

    def __str__(self):
        return f"{self.vectorString()} | Score {self.baseScore}"
    
class CVSSv2Metric(CVSSMetric):
    
    accessVector: str
    accessComplexity: str
    authentication: str
    acInsufInfo: bool
    obtainAllPrivilege: bool
    obtainUserPrivilege: bool
    obtainOtherPrivilege: bool
    userInteractionRequired: bool

    def __init__(self, data):
        super().__init__(data)
        self.baseSeverity = data['baseSeverity']
        self.accessVector = data['cvssData']['accessVector']
        self.accessComplexity = data['cvssData']['accessComplexity']
        self.authentication = data['cvssData']['authentication']
        self.acInsufInfo = data['acInsufInfo']
        self.obtainAllPrivilege = data['obtainAllPrivilege']
        self.obtainUserPrivilege = data['obtainUserPrivilege']
        self.obtainOtherPrivilege = data['obtainOtherPrivilege']
        self.userInteractionRequired = data['userInteractionRequired']
    
    def vectorString(self):
        return f"CVSS:{self.version}/AV:{self.accessVector[0]}/AC:{self.accessComplexity[0]}/Au:{self.authentication[0]}/C:{self.confidentialityImpact[0]}/I:{self.integrityImpact[0]}/A:{self.availabilityImpact[0]}"

    def __str__(self):
        return f"{self.vectorString()} | Score {self.baseScore}"

class CVSSv3Metric(CVSSMetric): # Same class for v3.0 and v3.1
    
    # Exploitability Metrics
    attackVector: str
    attackComplexity: str
    privilegesRequired: str
    userInteraction: str
    scope: str

    def __init__(self, data):
        super().__init__(data)

        self.baseSeverity = data['cvssData']['baseSeverity']
        self.attackVector = data['cvssData']['attackVector']
        self.attackComplexity = data['cvssData']['attackComplexity']
        self.privilegesRequired = data['cvssData']['privilegesRequired']    
        self.userInteraction = data['cvssData']['userInteraction']
        self.scope = data['cvssData']['scope']

    def vectorString(self):
        return f"CVSS:{self.version}/AV:{self.attackVector[0]}/AC:{self.attackComplexity[0]}/PR:{self.privilegesRequired[0]}/UI:{self.userInteraction[0]}/S:{self.scope[0]}/C:{self.confidentialityImpact[0]}/I:{self.integrityImpact[0]}/A:{self.availabilityImpact[0]}"
        