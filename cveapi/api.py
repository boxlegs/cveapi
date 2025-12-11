import requests
from cveapi import CVE, CVSSv2Metric, CVSSv3Metric, CVSSv4Metric
from datetime import datetime
from typing import Optional, List, Dict, Any

def call_cve_api(parameters):
    try:
        resp =  requests.get('https://services.nvd.nist.gov/rest/json/cves/2.0', params=parameters)
        resp.raise_for_status()
        return resp
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None

def parse_cve(data: dict) -> CVE:
    """
    Parse a single CVE entry from NVD API response.
    """
    return CVE(data.get('cve'))

def parse_cves(data: dict) -> list[CVE]:
    """
    Parse multiple CVE entries from NVD API response.
    """
    return [parse_cve(cve) for cve in data.get('vulnerabilities')]


def get_cve_by_id(cve_id):
    """
    Get a single CVE by its ID. 
    """
    if not cve_id.startswith('CVE-'):
        raise ValueError("CVE ID must start with 'CVE-'")
    req = call_cve_api({'cveId': cve_id})
    if req.status_code == 200:
        return parse_cve(req.json().get('vulnerabilities')[0])

def get_cves(
    cve_tag: Optional[str] = None,
    keyword: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    severity: Optional[str] = None,
    cvss_metrics: Optional[str] = None,
    cvss_version: str = '3',
    cpe_name: Optional[str] = None,
    is_vulnerable: Optional[bool] = None,
    cwe_id: Optional[str] = None,
    hasCertAlerts: Optional[bool] = None,
    hasCertNotes: Optional[bool] = None,
    noRejected: Optional[bool] = None
) -> List[CVE]:
    """
    Fetch CVEs with various filters.

    Args:
        cve_tag (str, optional): Filter by CVE tag.
        keyword (str, optional): Filter by keyword.
        start_date (datetime, optional): Filter by publication start date.
        end_date (datetime, optional): Filter by publication end date. Defaults to datetime.now() if not provided with start_date.
        cvss_severity (str, optional): Filter by CVSS severity category.
        cvss_version (str, optional): CVSS version for severity filter. Only one can be filtered at a time.
        cvss_metrics (str, optional): Filter by CVSS metrics vectorstring for the given CVSS version.
        cpe_name (str, optional): Filter by CPE name.
        is_vulnerable (bool, optional): Return only CVE associated with provided cpe_name if it is vulnerable.
        cwe_id (str, optional): Filter by CWE ID.
        hasCertAlerts (bool, optional): Filter by presence of US-CERT certification alerts.
        hasCertNotes (bool, optional): Filter by presence of US-CERT certification notes.
        noRejected (bool, optional): Exclude rejected CVEs.
    Returns:
        List[CVE]: List of matching CVE objects.
    """
    params: Dict[str, Any] = {}

    # Filter Params
    if cve_tag:
        params['cveTag'] = cve_tag
    if keyword:
        params['keywordSearch'] = keyword
    if start_date:
        params['pubStartDate'] = start_date.isoformat()
        if end_date:
            params['pubEndDate'] = end_date.isoformat()
        else:
            params['pubEndDate'] = datetime.now().isoformat()
    if cvss_version:
        if severity:
            params[f'cvssV{cvss_version}Severity'] = severity
        if cvss_metrics:
            params[f'cvssV{cvss_version}Metrics'] = cvss_metrics
    
    if cwe_id:
        params['cweId'] = cwe_id

    # CPE logic

    if cpe_name:
        params['cpeName'] = cpe_name
        if is_vulnerable:
            params['isVulnerable'] = None

    # Flags
    if hasCertAlerts:
        params['hasCertAlerts'] = None
    if hasCertNotes:
        params['hasCertNotes'] = None
    if noRejected:
        params['noRejected'] = None


    req = call_cve_api(params)
    if req and req.status_code == 200:
        return parse_cves(req.json())
    return []