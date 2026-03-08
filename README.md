<p align="center">
  <img src="docs/banner.svg" alt="GCP CNAPP Security Scanner" width="900"/>
</p>

<p align="center">
  <strong>A Python-based Cloud-Native Application Protection Platform (CNAPP) scanner for Google Cloud Platform</strong>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/license-MIT-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/checks-67%2B-4285f4?style=flat-square"/>
  <img src="https://img.shields.io/badge/CNAPP-CSPM%20%2B%20CIEM%20%2B%20CWPP%20%2B%20IaC-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/CIS_GCP_Benchmark-v2.0-34a853?style=flat-square"/>
</p>

---

## Overview

**GCP CNAPP Security Scanner** is a comprehensive offline security assessment tool that mimics a modern Cloud-Native Application Protection Platform (CNAPP) — combining CSPM, CIEM, CWPP, KSPM, and IaC security scanning into one unified scanner. It analyzes GCP configuration exports (JSON from `gcloud` CLI) against the CIS Google Cloud Foundation Benchmark v2.0, Google Cloud security best practices, and industry frameworks.

### What is CNAPP?

A Cloud-Native Application Protection Platform (CNAPP) — as defined by Gartner — unifies multiple cloud security capabilities into a single platform:

| Pillar | Full Name | What It Protects |
|--------|-----------|-----------------|
| **CSPM** | Cloud Security Posture Management | Infrastructure misconfigurations, compliance |
| **CIEM** | Cloud Infrastructure Entitlement Management | IAM permissions, least privilege, identity risk |
| **CWPP** | Cloud Workload Protection Platform | VMs, containers, serverless runtime security |
| **KSPM** | Kubernetes Security Posture Management | GKE cluster configuration, RBAC, network policy |
| **IaC** | Infrastructure as Code Security | Terraform misconfigurations before deployment |

This scanner covers **all five pillars** with 67+ checks across 15 modules — zero external dependencies, pure Python 3.8+ stdlib.

---

## CNAPP Modules (15)

### CSPM — Cloud Security Posture Management (7 modules, 39 checks)

<details>
<summary>🔑 <strong>Module 1: IAM & Organization Policy</strong> — 8 checks (CIS 1.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Service accounts with admin/owner roles | IAM-001 | CRITICAL | 1.5 | SAs should not hold Owner or Admin roles |
| Primitive (basic) roles in use | IAM-002 | HIGH | 1.4 | Owner/Editor/Viewer are overly broad |
| Separation of duties violations | IAM-003 | HIGH | 1.8 | SA Admin + SA User/Token Creator conflict |
| KMS admin and crypto role overlap | IAM-004 | HIGH | 1.11 | Same user can manage and use keys |
| Excessive SA Admin users | IAM-005 | MEDIUM | 1.6 | >3 users with SA admin role |
| Admin roles without IAM conditions | IAM-006 | MEDIUM | — | No time/resource scoping on admin bindings |
| Domain restricted sharing not enforced | IAM-007 | HIGH | 1.1 | External identities can access resources |
| Essential Contacts not configured | IAM-008 | LOW | 1.16 | No security notification contacts |
</details>

<details>
<summary>🌐 <strong>Module 2: Network & VPC Security</strong> — 8 checks (CIS 3.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Default VPC network exists | NET-001 | HIGH | 3.1 | Permissive auto-created firewall rules |
| SSH open to internet (0.0.0.0/0) | NET-002 | CRITICAL | 3.6 | Port 22 exposed to all IPs |
| RDP open to internet | NET-003 | CRITICAL | 3.7 | Port 3389 exposed to all IPs |
| Firewall allows all traffic from internet | NET-004 | CRITICAL | 3.8 | All protocols/ports from 0.0.0.0/0 |
| Subnets without VPC Flow Logs | NET-005 | HIGH | 3.8 | Network monitoring blind spots |
| Subnets without Private Google Access | NET-006 | MEDIUM | 3.9 | VMs need public IPs for Google APIs |
| Legacy networks detected | NET-007 | HIGH | 3.2 | Missing modern VPC features |
| Load balancers without SSL policy | NET-008 | MEDIUM | — | Weak TLS/cipher suites possible |
</details>

<details>
<summary>💻 <strong>Module 3: Compute Engine Security</strong> — 6 checks (CIS 4.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| VMs using default SA with full scope | COMP-001 | CRITICAL | 4.1 | Default SA + cloud-platform = project owner |
| VMs with public IP addresses | COMP-002 | HIGH | 4.9 | Direct internet exposure |
| Serial port access enabled | COMP-003 | MEDIUM | 4.5 | Interactive console access risk |
| Shielded VM not enabled | COMP-004 | MEDIUM | 4.8 | No boot integrity / vTPM |
| OS Login not enabled project-wide | COMP-005 | HIGH | 4.4 | SSH keys not centrally managed via IAM |
| Disks without CMEK encryption | COMP-006 | MEDIUM | 4.7 | Google-managed keys only |
</details>

<details>
<summary>📦 <strong>Module 4: Cloud Storage Security</strong> — 5 checks (CIS 5.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Publicly accessible buckets | STOR-001 | CRITICAL | 5.1 | allUsers / allAuthenticatedUsers ACL |
| Uniform Bucket-Level Access not enabled | STOR-002 | HIGH | 5.2 | Mixed ACL + IAM permissions |
| Buckets without access logging | STOR-003 | MEDIUM | 5.3 | No access audit trail |
| Missing retention policies | STOR-004 | LOW | — | No data lifecycle management |
| Buckets without CMEK encryption | STOR-005 | MEDIUM | — | Google-managed keys only |
</details>

<details>
<summary>🗄️ <strong>Module 5: Cloud SQL & Database Security</strong> — 5 checks (CIS 6.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Cloud SQL with public IPs | DB-001 | HIGH | 6.5 | Database exposed to internet |
| SSL not enforced | DB-002 | HIGH | 6.4 | Unencrypted database connections |
| Authorized networks include 0.0.0.0/0 | DB-003 | CRITICAL | 6.5 | Database open to all IPs |
| Automated backups not enabled | DB-004 | HIGH | 6.7 | No disaster recovery |
| Security flags not set | DB-005 | MEDIUM | 6.1 | PostgreSQL log_checkpoints, MySQL local_infile |
</details>

<details>
<summary>📊 <strong>Module 6: Logging & Monitoring</strong> — 5 checks (CIS 2.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Audit logging not configured | LOG-001 | HIGH | 2.1 | Cloud Audit Logs verification |
| Insufficient audit log coverage | LOG-002 | HIGH | 2.1 | Data Access logs not enabled for all services |
| No log sinks (exports) configured | LOG-003 | HIGH | 2.2 | Logs not exported to BigQuery/Storage/SIEM |
| No log-based metrics | LOG-004 | HIGH | 2.4 | No metrics for IAM/firewall/config changes |
| No alerting policies | LOG-005 | HIGH | 2.4 | No automated security event alerts |
</details>

<details>
<summary>📈 <strong>Module 7: BigQuery Security</strong> — 2 checks (CIS 7.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Datasets with broad access | BQ-001 | HIGH | 7.1 | allAuthenticatedUsers dataset access |
| Datasets without CMEK | BQ-002 | MEDIUM | 7.2 | Google-managed encryption |
</details>

---

### CIEM — Cloud Infrastructure Entitlement Management (2 modules, 8 checks)

<details>
<summary>👤 <strong>Module 8: IAM Entitlements & Least Privilege</strong> — 4 checks</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| Users with excessive roles (>10) | CIEM-001 | HIGH | — | Over-privileged users |
| Custom roles review | CIEM-002 | LOW | — | Review with IAM Recommender |
| External @gmail.com identities | CIEM-003 | HIGH | 1.1 | Non-org accounts with access |
| allUsers/allAuthenticatedUsers at project level | CIEM-004 | CRITICAL | 1.2 | Public project-level access |
</details>

<details>
<summary>🔧 <strong>Module 9: Service Account Security</strong> — 4 checks (CIS 1.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| SA keys older than 90 days | SA-001 | HIGH | 1.7 | Key rotation required |
| User-managed SA keys exist | SA-002 | MEDIUM | 1.4 | Prefer Workload Identity |
| Disabled SAs not cleaned up | SA-003 | LOW | — | Dead service accounts |
| Excessive SA impersonation permissions | SA-004 | HIGH | 1.6 | Many Token Creator users |
</details>

---

### CWPP — Cloud Workload Protection (3 modules, 14 checks)

<details>
<summary>☸️ <strong>Module 10: GKE / Kubernetes Security (KSPM)</strong> — 9 checks</summary>

| Check | ID | Severity | CIS GKE | Description |
|-------|-----|----------|---------|-------------|
| Legacy ABAC enabled | GKE-001 | HIGH | 5.8.1 | Bypasses RBAC controls |
| Network Policy not configured | GKE-002 | HIGH | 5.6.7 | No pod-to-pod segmentation |
| Public nodes (not private cluster) | GKE-003 | HIGH | 5.4.1 | Nodes exposed to internet |
| Workload Identity not enabled | GKE-004 | HIGH | 5.2.1 | No per-pod IAM binding |
| Shielded GKE Nodes disabled | GKE-005 | MEDIUM | 5.5.1 | No node integrity verification |
| Binary Authorization not enabled | GKE-006 | MEDIUM | 5.9.1 | Unsigned images can deploy |
| Basic authentication on API server | GKE-007 | CRITICAL | 5.1.1 | Username/password for K8s API |
| Node auto-upgrade disabled | GKE-008 | MEDIUM | 5.5.3 | Nodes may run vulnerable versions |
</details>

<details>
<summary>⚡ <strong>Module 11: Cloud Functions / Serverless Security</strong> — 3 checks</summary>

| Check | ID | Severity | Description |
|-------|-----|----------|-------------|
| Functions publicly invocable (allUsers) | FN-001 | HIGH | No authentication required |
| Functions with ALLOW_ALL ingress | FN-002 | MEDIUM | Accepts traffic from any source |
| Functions using default App Engine SA | FN-003 | HIGH | Default SA has Editor role |
</details>

<details>
<summary>🐳 <strong>Module 12: Container Security</strong> — 2 checks</summary>

| Check | ID | Severity | Description |
|-------|-----|----------|-------------|
| Container Analysis API not enabled | CONT-001 | MEDIUM | No automated vulnerability scanning |
| Images in legacy gcr.io | CONT-002 | LOW | Migrate to Artifact Registry |
</details>

---

### IaC — Infrastructure as Code Security (1 module, 2 checks)

<details>
<summary>📝 <strong>Module 13: Terraform / IaC Security</strong> — 2 checks</summary>

| Check | ID | Severity | Description |
|-------|-----|----------|-------------|
| Terraform state misconfigurations | IAC-001 | HIGH | Scans for 0.0.0.0/0, allUsers, cloud-platform scope, legacy ABAC, SSL disabled |
| Terraform plan resource deletions | IAC-002 | MEDIUM | Flags destructive changes |
</details>

---

### Compliance & Encryption (2 modules, 4 checks)

<details>
<summary>📋 <strong>Module 14: CIS Benchmark Compliance</strong> — 1 check</summary>

| Check | ID | Description |
|-------|-----|-------------|
| CIS GCP Foundation v2.0 assessment summary | CIS-001 | Coverage across sections 1-7 |
</details>

<details>
<summary>🔐 <strong>Module 15: KMS & Encryption</strong> — 3 checks (CIS 1.x)</summary>

| Check | ID | Severity | CIS | Description |
|-------|-----|----------|-----|-------------|
| KMS keys without rotation period | KMS-001 | HIGH | 1.10 | Keys not automatically rotated |
| KMS keys with public access | KMS-002 | CRITICAL | 1.9 | allUsers can use encryption keys |
| KMS admin and crypto role overlap | KMS-003 | HIGH | 1.11 | SoD violation on key management |
</details>

---

## Quick Start

```bash
git clone https://github.com/Krishcalin/GCP-CNAPP-Security-Scanner.git
cd GCP-CNAPP-Security-Scanner

# Run with sample data (includes deliberate misconfigurations)
python gcp_scanner.py --data-dir ./sample_data --output report.html

# Run specific modules
python gcp_scanner.py --data-dir ./exports --modules iam network compute gke

# Filter by severity
python gcp_scanner.py --data-dir ./exports --severity HIGH

# Run only CIEM checks
python gcp_scanner.py --data-dir ./exports --modules ciem sa
```

---

## Exporting GCP Configurations

Use the `gcloud` CLI to export configurations from your GCP project. The scanner reads standard JSON exports.

### Core Exports (Recommended)
```bash
# IAM
gcloud projects get-iam-policy PROJECT_ID --format=json > iam_policy.json

# Network & VPC
gcloud compute networks list --format=json > vpc_networks.json
gcloud compute firewall-rules list --format=json > firewall_rules.json
gcloud compute networks subnets list --format=json > subnets.json

# Compute
gcloud compute instances list --format=json > compute_instances.json
gcloud compute disks list --format=json > disks.json

# Storage
gsutil ls -p PROJECT_ID -L -b 2>/dev/null > storage_buckets.json  # Or use API
gcloud storage buckets list --format=json > storage_buckets.json

# Cloud SQL
gcloud sql instances list --format=json > cloud_sql.json

# GKE
gcloud container clusters list --format=json > gke_clusters.json

# Service Accounts
gcloud iam service-accounts list --format=json > service_accounts.json
gcloud iam service-accounts keys list --iam-account=SA_EMAIL --format=json > sa_keys.json
```

### Extended Exports
```bash
# Logging & Monitoring
gcloud logging sinks list --format=json > log_sinks.json
gcloud alpha monitoring policies list --format=json > alert_policies.json

# BigQuery
bq ls --format=json > bigquery_datasets.json

# Cloud Functions
gcloud functions list --format=json > cloud_functions.json

# KMS
gcloud kms keys list --keyring=KEYRING --location=LOCATION --format=json > kms_keys.json

# Org Policy (requires org-level access)
gcloud resource-manager org-policies list --project=PROJECT_ID --format=json > org_policy.json

# APIs enabled
gcloud services list --enabled --format=json > apis_enabled.json
```

### Terraform State (for IaC scanning)
```bash
# Copy Terraform state for IaC analysis
cp terraform.tfstate /path/to/exports/
# Or export plan
terraform plan -out=tfplan && terraform show -json tfplan > terraform_plan.json
```

---

## Available Modules

```
CSPM:
  iam          — IAM & Organization Policy (CIS 1.x)
  network      — Network & VPC Security (CIS 3.x)
  compute      — Compute Engine Security (CIS 4.x)
  storage      — Cloud Storage Security (CIS 5.x)
  database     — Cloud SQL & Database Security (CIS 6.x)
  logging      — Logging & Monitoring (CIS 2.x)
  bigquery     — BigQuery Security (CIS 7.x)

CIEM:
  ciem         — IAM Entitlements & Least Privilege
  sa           — Service Account Security (CIS 1.x)

CWPP:
  gke          — GKE / Kubernetes Security (CIS GKE)
  serverless   — Cloud Functions Security
  container    — Container Image Security

IaC:
  iac          — Terraform / IaC Misconfiguration Scanning

Compliance:
  cis          — CIS GCP Foundation Benchmark Summary
  kms          — KMS & Encryption Security (CIS 1.x)

all            — Run all 15 modules (default)
```

---

## Project Structure

```
GCP-CNAPP-Security-Scanner/
├── gcp_scanner.py                  # Main entry point
├── modules/
│   ├── base.py                     # Data loader & base auditor
│   ├── cspm_core.py               # IAM, Network, Compute, Storage (CIS 1,3,4,5)
│   ├── cspm_ciem.py               # Database, Logging, BigQuery, CIEM, SA (CIS 2,6,7)
│   ├── cwpp_iac.py                # GKE, Serverless, Container, IaC, CIS, KMS
│   └── report_generator.py        # Interactive HTML dashboard report
├── sample_data/                    # 19 demo GCP config exports
│   ├── iam_policy.json            # Project IAM bindings
│   ├── firewall_rules.json        # Compute firewall rules
│   ├── compute_instances.json     # VM instances
│   ├── storage_buckets.json       # GCS buckets
│   ├── cloud_sql.json             # SQL instances
│   ├── gke_clusters.json          # Kubernetes clusters
│   ├── cloud_functions.json       # Serverless functions
│   ├── kms_keys.json              # Encryption keys
│   ├── terraform.tfstate          # Terraform state
│   └── ...                        # 10 more config files
├── docs/
│   └── banner.svg                 # Project banner
├── .gitignore
├── LICENSE
├── CONTRIBUTING.md
└── README.md
```

---

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                    GCP Configuration Exports                     │
│   gcloud CLI JSON  ·  Terraform State  ·  API Responses          │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │    Data Loader       │
                    │  (modules/base.py)   │
                    └──────────┬──────────┘
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                     │
   ┌──────▼──────┐    ┌───────▼───────┐    ┌───────▼───────┐
   │    CSPM      │    │    CIEM       │    │    CWPP       │
   │  7 modules   │    │  2 modules    │    │  3 modules    │
   │  39 checks   │    │  8 checks     │    │  14 checks    │
   └──────┬──────┘    └───────┬───────┘    └───────┬───────┘
          │                    │                     │
          └────────────────────┼────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  + IaC (2 checks)   │
                    │  + KMS (3 checks)   │
                    │  + CIS (1 check)    │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  HTML Report        │
                    │  Dashboard          │
                    └─────────────────────┘
```

---

## CIS GCP Foundation Benchmark Coverage

The scanner maps checks to the CIS Google Cloud Computing Platform Foundation Benchmark v2.0:

| CIS Section | Topic | Module | Checks |
|-------------|-------|--------|--------|
| 1.x | Identity and Access Management | `iam`, `ciem`, `sa`, `kms` | 19 |
| 2.x | Logging and Monitoring | `logging` | 5 |
| 3.x | Networking | `network` | 8 |
| 4.x | Virtual Machines | `compute` | 6 |
| 5.x | Storage | `storage` | 5 |
| 6.x | Cloud SQL Database Services | `database` | 5 |
| 7.x | BigQuery | `bigquery` | 2 |

Additional coverage beyond CIS: GKE/KSPM (CIS GKE Benchmark), Serverless, Container, IaC, and CIEM checks.

---

## References

### CIS Benchmarks
- [CIS Google Cloud Platform Foundation Benchmark v2.0](https://www.cisecurity.org/benchmark/google_cloud_computing_platform)
- [CIS Google Kubernetes Engine (GKE) Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [GCP CIS InSpec Profile (Google Official)](https://github.com/GoogleCloudPlatform/inspec-gcp-cis-benchmark)

### Google Cloud Security
- [GCP Security Best Practices](https://cloud.google.com/security/best-practices)
- [GCP Security Command Center — Vulnerability Findings](https://docs.cloud.google.com/security-command-center/docs/concepts-vulnerabilities-findings)
- [GCP IAM Best Practices](https://cloud.google.com/iam/docs/using-iam-securely)
- [GKE Hardening Guide](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster)
- [GCP VPC Firewall Rules Best Practices](https://cloud.google.com/vpc/docs/firewalls)

### Industry Frameworks
- [NIST SP 800-53 Rev 5](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [NIST Cybersecurity Framework (CSF) 2.0](https://www.nist.gov/cyberframework)
- [SOC 2 — Trust Service Criteria](https://www.aicpa.org/interestareas/frc/assuranceadvisoryservices/sorhome)
- [ISO/IEC 27001:2022](https://www.iso.org/standard/27001)

### CNAPP Architecture
- [Gartner — Market Guide for CNAPP](https://www.gartner.com/en/documents/4017050)
- [Wiz — What is CSPM](https://www.wiz.io/academy/what-is-cloud-security-posture-management-cspm)
- [Orca — CWPP, CSPM, CIEM, CNAPP](https://orca.security/resources/blog/cwpp-cspm-ciem-cnapp/)
- [Sysdig — Who's Who in Cloud Security](https://www.sysdig.com/blog/cnapp-cloud-security-sysdig)

---

## Disclaimer

This tool is for **authorized security assessments only**. It performs offline analysis of JSON configuration exports and does not connect to any live GCP environment. Always ensure you have proper authorization before exporting and analyzing cloud configurations.

---

## License

MIT License — see [LICENSE](LICENSE).
