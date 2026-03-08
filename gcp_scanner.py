#!/usr/bin/env python3
"""
GCP CNAPP Security Scanner
=============================
Cloud-Native Application Protection Platform for Google Cloud.
CSPM · CIEM · CWPP · IaC · KSPM · CIS Benchmark

Usage:
    python gcp_scanner.py --data-dir ./sample_data --output report.html
    python gcp_scanner.py --data-dir ./exports --modules iam network compute gke
"""
import argparse,json,sys,datetime
from pathlib import Path
from modules.base import DataLoader
from modules.cspm_core import IamOrgAuditor,NetworkVpcAuditor,ComputeAuditor,StorageAuditor
from modules.cspm_ciem import (DatabaseAuditor,LoggingMonitoringAuditor,BigQueryAuditor,
    CiemEntitlementsAuditor,ServiceAccountAuditor)
from modules.cwpp_iac import (GkeSecurityAuditor,ServerlessAuditor,ContainerSecurityAuditor,
    IacSecurityAuditor,CisBenchmarkAuditor,KmsEncryptionAuditor)

try: from modules.report_generator import ReportGenerator
except ImportError: ReportGenerator=None

def banner():
    print(r"""
  ╔═══════════════════════════════════════════════════════════════════════╗
  ║   GCP CNAPP Security Scanner v1.0                                    ║
  ║   Cloud-Native Application Protection Platform                       ║
  ║                                                                      ║
  ║   CSPM · CIEM · CWPP · KSPM · IaC · CIS Benchmark                  ║
  ║   IAM · VPC · GCE · GCS · SQL · GKE · Functions · KMS · Terraform   ║
  ╚═══════════════════════════════════════════════════════════════════════╝
    """)

MODULE_MAP={
    "iam":       ("CSPM: IAM & Org Policy",IamOrgAuditor),
    "network":   ("CSPM: Network & VPC",NetworkVpcAuditor),
    "compute":   ("CSPM: Compute Engine",ComputeAuditor),
    "storage":   ("CSPM: Cloud Storage",StorageAuditor),
    "database":  ("CSPM: Cloud SQL & Database",DatabaseAuditor),
    "logging":   ("CSPM: Logging & Monitoring",LoggingMonitoringAuditor),
    "bigquery":  ("CSPM: BigQuery",BigQueryAuditor),
    "ciem":      ("CIEM: IAM Entitlements",CiemEntitlementsAuditor),
    "sa":        ("CIEM: Service Account Security",ServiceAccountAuditor),
    "gke":       ("CWPP/KSPM: GKE Security",GkeSecurityAuditor),
    "serverless":("CWPP: Serverless Security",ServerlessAuditor),
    "container": ("CWPP: Container Security",ContainerSecurityAuditor),
    "iac":       ("IaC: Terraform Security",IacSecurityAuditor),
    "cis":       ("Compliance: CIS Benchmark",CisBenchmarkAuditor),
    "kms":       ("Encryption: KMS & Keys",KmsEncryptionAuditor),
}

def main():
    banner()
    parser=argparse.ArgumentParser(description="GCP CNAPP Security Scanner")
    parser.add_argument("--data-dir",required=True)
    parser.add_argument("--output",default="gcp_security_report.html")
    parser.add_argument("--severity",choices=["CRITICAL","HIGH","MEDIUM","LOW","ALL"],default="ALL")
    parser.add_argument("--modules",nargs="+",choices=list(MODULE_MAP.keys())+["all"],default=["all"])
    parser.add_argument("--config",default=None)
    args=parser.parse_args()
    data_dir=Path(args.data_dir)
    if not data_dir.exists(): print(f"[ERROR] Not found: {data_dir}"); sys.exit(1)
    print("[*] Loading GCP configuration data...")
    data=DataLoader(data_dir).load_all()
    baseline={}
    if args.config:
        with open(args.config) as f: baseline=json.load(f)
    run=list(MODULE_MAP.keys()) if "all" in args.modules else args.modules
    all_findings=[]
    for mod in run:
        if mod not in MODULE_MAP: continue
        label,cls=MODULE_MAP[mod]
        print(f"[*] Running {label}...")
        findings=cls(data,baseline).run_all_checks()
        all_findings.extend(findings)
        print(f"    Found {len(findings)} issue(s)")
    sev={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    if args.severity!="ALL":
        t=sev.get(args.severity,3)
        all_findings=[f for f in all_findings if sev.get(f["severity"],3)<=t]
    meta={"scan_time":datetime.datetime.now().isoformat(),"data_directory":str(data_dir),
          "modules_run":run,"severity_filter":args.severity,"platform":"Google Cloud Platform"}
    print(f"\n[*] Generating report: {args.output}")
    if ReportGenerator: ReportGenerator(all_findings,meta).generate(args.output)
    else:
        with open(args.output.replace(".html",".json"),"w") as f:
            json.dump({"findings":all_findings,"meta":meta},f,indent=2)
    c=sum(1 for f in all_findings if f["severity"]=="CRITICAL")
    h=sum(1 for f in all_findings if f["severity"]=="HIGH")
    m=sum(1 for f in all_findings if f["severity"]=="MEDIUM")
    l=sum(1 for f in all_findings if f["severity"]=="LOW")
    print(f"\n{'='*71}")
    print(f"  SCAN COMPLETE — {len(all_findings)} finding(s)")
    print(f"  CRITICAL: {c}  |  HIGH: {h}  |  MEDIUM: {m}  |  LOW: {l}")
    print(f"  Report: {args.output}")
    print(f"{'='*71}\n")

if __name__=="__main__": main()
