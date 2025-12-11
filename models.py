from datetime import datetime

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

"""
Abstract class for CVSS Metrics
"""
class CVSSMetric:
    
    source: str
    type: str
    version: str
    baseScore: str
    baseSeverity: str

    # Impact Metrics
    confidentialityImpact: str
    integrityImpact: str
    availabilityImpact: str
    
    def __init__(self, data):
        self.source = data['source']
        self.type = data['type']
        self.version = data['cvssData']['version']
        self.baseScore = data['cvssData']['baseScore']

    def vectorString(self):
        pass

    def _short(self, attr):
        return 'X' if attr == 'NOT_DEFINED' else attr[0]

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
    exploitabilityScore: str
    impactScore: str

    def __init__(self, data):
        super().__init__(data)
        self.baseSeverity = data['baseSeverity']
        self.accessVector = data['cvssData']['accessVector']
        self.accessComplexity = data['cvssData']['accessComplexity']
        self.authentication = data['cvssData']['authentication']
        self.acInsufInfo = data['acInsufInfo']
        self.exploitabilityScore = data['exploitabilityScore']
        self.obtainAllPrivilege = data['obtainAllPrivilege']
        self.obtainUserPrivilege = data['obtainUserPrivilege']
        self.obtainOtherPrivilege = data['obtainOtherPrivilege']
        # self.userInteractionRequired = data['userInteractionRequired']
        self.impactScore = data['impactScore']
        self.confidentialityImpact = data['cvssData']['confidentialityImpact']
        self.integrityImpact = data['cvssData']['integrityImpact']
        self.availabilityImpact = data['cvssData']['availabilityImpact']

        
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
    exploitabilityScore: str
    impactScore: str

    def __init__(self, data):
        super().__init__(data)

        self.baseSeverity = data['cvssData']['baseSeverity']
        self.attackVector = data['cvssData']['attackVector']
        self.attackComplexity = data['cvssData']['attackComplexity']
        self.privilegesRequired = data['cvssData']['privilegesRequired']    
        self.userInteraction = data['cvssData']['userInteraction']
        self.exploitabilityScore = data['exploitabilityScore']
        self.scope = data['cvssData']['scope']
        self.impactScore = data['impactScore']
        self.confidentialityImpact = data['cvssData']['confidentialityImpact']
        self.integrityImpact = data['cvssData']['integrityImpact']
        self.availabilityImpact = data['cvssData']['availabilityImpact']

        
    def vectorString(self):
        return f"CVSS:{self.version}/AV:{self.attackVector[0]}/AC:{self.attackComplexity[0]}/PR:{self.privilegesRequired[0]}/UI:{self.userInteraction[0]}/S:{self.scope[0]}/C:{self.confidentialityImpact[0]}/I:{self.integrityImpact[0]}/A:{self.availabilityImpact[0]}"
        
class CVSSv4Metric(CVSSMetric):
    
    attackVector: str
    attackComplexity: str
    attackRequirements: str
    privilegesRequired: str

    def __init__(self, data):
        super().__init__(data)

        self.baseSeverity = data['cvssData']['baseSeverity']
        self.attackVector = data['cvssData']['attackVector']
        self.attackComplexity = data['cvssData']['attackComplexity']
        self.attackRequirements = data['cvssData']['attackRequirements']
        self.privilegesRequired = data['cvssData']['privilegesRequired']
        self.userInteraction = data['cvssData']['userInteraction']
        self.vulnConfidentialityImpact = data['cvssData']['vulnConfidentialityImpact']
        self.vulnIntegrityImpact = data['cvssData']['vulnIntegrityImpact']
        self.vulnAvailabilityImpact = data['cvssData']['vulnAvailabilityImpact']
        self.subConfidentialityImpact = data['cvssData']['subConfidentialityImpact']
        self.subIntegrityImpact = data['cvssData']['subIntegrityImpact']
        self.subAvailabilityImpact = data['cvssData']['subAvailabilityImpact']
        self.exploitMaturity = data['cvssData']['exploitMaturity']
        self.confidentialityRequirement = data['cvssData']['confidentialityRequirement']
        self.integrityRequirement = data['cvssData']['integrityRequirement']
        self.availabilityRequirement = data['cvssData']['availabilityRequirement']
        self.modifiedAttackVector = data['cvssData']['modifiedAttackVector']
        self.modifiedAttackComplexity = data['cvssData']['modifiedAttackComplexity']
        self.modifiedAttackRequirements = data['cvssData']['modifiedAttackRequirements']
        self.modifiedPrivilegesRequired = data['cvssData']['modifiedPrivilegesRequired']
        self.modifiedUserInteraction = data['cvssData']['modifiedUserInteraction']
        self.modifiedVulnConfidentialityImpact = data['cvssData']['modifiedVulnConfidentialityImpact']
        self.modifiedVulnIntegrityImpact = data['cvssData']['modifiedVulnIntegrityImpact']
        self.modifiedVulnAvailabilityImpact = data['cvssData']['modifiedVulnAvailabilityImpact']
        self.modifiedSubConfidentialityImpact = data['cvssData']['modifiedSubConfidentialityImpact']
        self.modifiedSubIntegrityImpact = data['cvssData']['modifiedSubIntegrityImpact']
        self.modifiedSubAvailabilityImpact = data['cvssData']['modifiedSubAvailabilityImpact']
        self.safety = data['cvssData']['Safety']
        self.automatable = data['cvssData']['Automatable']
        self.recovery = data['cvssData']['Recovery']
        self.valueDensity = data['cvssData']['valueDensity']
        self.vulnerabilityResponseEffort = data['cvssData']['vulnerabilityResponseEffort']
        self.providerUrgency = data['cvssData']['providerUrgency']
   
    def vectorString(self):

        baseMetrics = (
                        f"/AV:{self._short(self.attackVector)}"
                        f"/AC:{self._short(self.attackComplexity)}"
                        f"/AT:{self._short(self.attackRequirements)}"
                        f"/PR:{self._short(self.privilegesRequired)}"
                        f"/UI:{self._short(self.userInteraction)}"
                    )
        
        threatMetrics = (
                        f"/VC:{self._short(self.vulnConfidentialityImpact)}"
                        f"/VI:{self._short(self.vulnIntegrityImpact)}"
                        f"/VA:{self._short(self.vulnAvailabilityImpact)}"
        )
        
        subMetrics = (
                        f"/SC:{self._short(self.subConfidentialityImpact)}"
                        f"/SI:{self._short(self.subIntegrityImpact)}"
                        f"/SA:{self._short(self.subAvailabilityImpact)}"
        )

        maturityMetrics = f"/E:{self._short(self.exploitMaturity)}"
        environmentalMetrics = (
                        f"/CR:{self._short(self.confidentialityRequirement)}"
                        f"/IR:{self._short(self.integrityRequirement)}"
                        f"/AR:{self._short(self.availabilityRequirement)}"
        )

        modifiedMetrics = (
                        f"/MAV:{self._short(self.modifiedAttackVector)}"
                        f"/MAC:{self._short(self.modifiedAttackComplexity)}"
                        f"/MAR:{self._short(self.modifiedAttackRequirements)}"
                        f"/MPR:{self._short(self.modifiedPrivilegesRequired)}"
                        f"/MUI:{self._short(self.modifiedUserInteraction)}"
                        f"/MVC:{self._short(self.modifiedVulnConfidentialityImpact)}"
                        f"/MVI:{self._short(self.modifiedVulnIntegrityImpact)}"
                        f"/MVA:{self._short(self.modifiedVulnAvailabilityImpact)}"
                        f"/MSC:{self._short(self.modifiedSubConfidentialityImpact)}"
                        f"/MSI:{self._short(self.modifiedSubIntegrityImpact)}"
                        f"/MSA:{self._short(self.modifiedSubAvailabilityImpact)}"
        )

        suppMetrics = (
                        f"/S:{self._short(self.safety)}"
                        f"/AU:{self._short(self.automatable)}"
                        f"/R:{self._short(self.recovery)}"
                        f"/V:{self._short(self.valueDensity)}"
                        f"/RE:{self._short(self.vulnerabilityResponseEffort)}"
                        f"/U:{self._short(self.providerUrgency)}"
        )

        return f"CVSS:{self.version}" + baseMetrics + threatMetrics + subMetrics + maturityMetrics + environmentalMetrics + modifiedMetrics + suppMetrics
