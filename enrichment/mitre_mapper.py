"""
ARGUN CTI — MITRE ATT&CK Mapper
Maps CWE (Common Weakness Enumeration) to MITRE ATT&CK techniques.
"""

import logging

logger = logging.getLogger("argun-cti.mitre")

# CWE → MITRE ATT&CK technique mapping (most common mappings)
CWE_TO_ATTACK = {
    # Injection
    "CWE-78": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-79": [{"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"}],
    "CWE-89": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-94": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
    "CWE-77": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],

    # Authentication / Authorization
    "CWE-287": [{"id": "T1078", "name": "Valid Accounts", "tactic": "Initial Access"}],
    "CWE-306": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],
    "CWE-798": [{"id": "T1078.001", "name": "Default Accounts", "tactic": "Initial Access"}],
    "CWE-862": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],
    "CWE-863": [{"id": "T1548", "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}],

    # Memory Corruption
    "CWE-119": [{"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-120": [{"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-122": [{"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-125": [{"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-416": [{"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],
    "CWE-787": [{"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"}],

    # File / Path
    "CWE-22": [{"id": "T1083", "name": "File and Directory Discovery", "tactic": "Discovery"}],
    "CWE-434": [{"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"}],

    # Deserialization
    "CWE-502": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],

    # Information Disclosure
    "CWE-200": [{"id": "T1005", "name": "Data from Local System", "tactic": "Collection"}],
    "CWE-209": [{"id": "T1005", "name": "Data from Local System", "tactic": "Collection"}],
    "CWE-532": [{"id": "T1005", "name": "Data from Local System", "tactic": "Collection"}],

    # SSRF
    "CWE-918": [{"id": "T1090", "name": "Proxy", "tactic": "Command and Control"}],

    # Cryptographic Issues
    "CWE-295": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],
    "CWE-327": [{"id": "T1557", "name": "Adversary-in-the-Middle", "tactic": "Credential Access"}],

    # Privilege Escalation
    "CWE-269": [{"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"}],

    # XXE
    "CWE-611": [{"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}],

    # CSRF
    "CWE-352": [{"id": "T1189", "name": "Drive-by Compromise", "tactic": "Initial Access"}],

    # Race Condition
    "CWE-362": [{"id": "T1068", "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"}],

    # Misconfiguration
    "CWE-16": [{"id": "T1574", "name": "Hijack Execution Flow", "tactic": "Persistence"}],

    # Template Injection
    "CWE-1336": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
}


class MITREMapper:
    def map_cwe_to_attack(self, cwes):
        """
        Map a list of CWE IDs to MITRE ATT&CK techniques.
        Input: ["CWE-79", "CWE-89"]
        Output: [{"id": "T1189", "name": "...", "tactic": "..."}]
        """
        techniques = []
        seen_ids = set()

        for cwe in cwes:
            cwe = cwe.strip().upper()
            if cwe in CWE_TO_ATTACK:
                for tech in CWE_TO_ATTACK[cwe]:
                    if tech["id"] not in seen_ids:
                        techniques.append(tech)
                        seen_ids.add(tech["id"])

        return techniques
