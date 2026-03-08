"""Base Auditor and GCP Configuration Data Loader for CNAPP Scanner."""
import csv, json, datetime
from pathlib import Path
from typing import Dict, List, Any

class BaseAuditor:
    SEVERITY_CRITICAL="CRITICAL"; SEVERITY_HIGH="HIGH"; SEVERITY_MEDIUM="MEDIUM"; SEVERITY_LOW="LOW"
    def __init__(self, data, baseline=None):
        self.data=data; self.baseline=baseline or {}; self.findings=[]
    def finding(self, cid, title, sev, cat, desc, items=None, remed="", refs=None, cis=None, details=None, remediation=None, references=None):
        f={"check_id":cid,"title":title,"severity":sev,"category":cat,"description":desc,
           "affected_items":items or [],"affected_count":len(items) if items else 0,
           "remediation":remediation or remed,"references":references or refs or [],"cis_benchmark":cis or "",
           "details":details or {},"timestamp":datetime.datetime.now().isoformat()}
        self.findings.append(f); return f
    def run_all_checks(self)->List[Dict]: raise NotImplementedError
    def gb(self,k,d): return self.baseline.get(k,d)

FILE_MAP={
    # IAM & Org
    "iam_policy":["iam_policy.json","project_iam.json"],
    "org_policy":["org_policy.json","organization_policy.json"],
    "service_accounts":["service_accounts.json","sa_list.json"],
    "sa_keys":["sa_keys.json","service_account_keys.json"],
    # Networking
    "vpc_networks":["vpc_networks.json","networks.json"],
    "firewall_rules":["firewall_rules.json","firewalls.json"],
    "subnets":["subnets.json","subnetworks.json"],
    "load_balancers":["load_balancers.json"],
    "dns_config":["dns_config.json","dns_policies.json"],
    # Compute
    "compute_instances":["compute_instances.json","instances.json"],
    "instance_templates":["instance_templates.json"],
    "disks":["disks.json","compute_disks.json"],
    # Storage
    "storage_buckets":["storage_buckets.json","buckets.json"],
    "bucket_iam":["bucket_iam.json","bucket_policies.json"],
    # Database
    "cloud_sql":["cloud_sql.json","sql_instances.json"],
    "spanner":["spanner.json"],
    "bigtable":["bigtable.json"],
    # Logging & Monitoring
    "log_sinks":["log_sinks.json","sinks.json"],
    "log_metrics":["log_metrics.json","metrics.json"],
    "alert_policies":["alert_policies.json","alerts.json"],
    "audit_config":["audit_config.json","audit_log_config.json"],
    # BigQuery
    "bigquery_datasets":["bigquery_datasets.json","datasets.json"],
    # GKE / Kubernetes
    "gke_clusters":["gke_clusters.json","kubernetes_clusters.json"],
    # Cloud Functions
    "cloud_functions":["cloud_functions.json","functions.json"],
    # KMS
    "kms_keys":["kms_keys.json","crypto_keys.json"],
    "kms_keyrings":["kms_keyrings.json"],
    # IaC
    "terraform_state":["terraform.tfstate","terraform_state.json"],
    "terraform_plan":["terraform_plan.json","tfplan.json"],
    # Container
    "container_images":["container_images.json","artifacts.json"],
    # General
    "project_config":["project_config.json","project.json"],
    "apis_enabled":["apis_enabled.json","services.json"],
}

class DataLoader:
    def __init__(self, data_dir):
        self.data_dir=Path(data_dir); self._data={}
    def load_all(self):
        for key,fnames in FILE_MAP.items():
            for fn in fnames:
                fp=self.data_dir/fn
                if fp.exists():
                    print(f"    Loading {fn}...")
                    try:
                        with open(fp,"r",encoding="utf-8-sig") as f: self._data[key]=json.load(f)
                    except Exception as e: print(f"    [WARN] {e}"); self._data[key]=None
                    break
            else: self._data[key]=None
        loaded=sum(1 for v in self._data.values() if v is not None)
        print(f"    Loaded: {loaded}/{len(FILE_MAP)} config files")
        return self._data
