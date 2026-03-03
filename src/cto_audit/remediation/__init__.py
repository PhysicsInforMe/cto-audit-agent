"""
Remediation Pipeline — Knowledge Base, Simulator e Context Collector.

Componenti:
- RemediationLoader: carica KB da YAML con lookup per rule_id e stack-specific merging
- WhatIfSimulator: simula rimozione finding e proiezione score
- ContextCollector: inferisce contesto progetto da dati audit
"""
