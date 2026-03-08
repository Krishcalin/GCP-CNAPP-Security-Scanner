<p align="center"><strong>GCP CNAPP Security Scanner v1.0</strong></p>
<p align="center">Cloud-Native Application Protection Platform for Google Cloud</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/dependencies-zero-brightgreen?style=flat-square"/>
  <img src="https://img.shields.io/badge/checks-75%2B-4285f4?style=flat-square"/>
  <img src="https://img.shields.io/badge/CNAPP-CSPM%20%2B%20CIEM%20%2B%20CWPP%20%2B%20IaC-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/CIS_GCP-v2.0-green?style=flat-square"/>
</p>

## CNAPP Pillars & Modules (15)

### CSPM (Cloud Security Posture Management)
| Module | Key | Checks | CIS Section |
|--------|-----|--------|-------------|
| IAM & Org Policy | `iam` | 8 | CIS 1.x |
| Network & VPC | `network` | 8 | CIS 3.x |
| Compute Engine | `compute` | 6 | CIS 4.x |
| Cloud Storage | `storage` | 5 | CIS 5.x |
| Cloud SQL | `database` | 5 | CIS 6.x |
| Logging & Monitoring | `logging` | 5 | CIS 2.x |
| BigQuery | `bigquery` | 2 | CIS 7.x |

### CIEM (Cloud Infrastructure Entitlement Management)
| Module | Key | Checks |
|--------|-----|--------|
| IAM Entitlements | `ciem` | 4 |
| Service Account Security | `sa` | 4 |

### CWPP (Cloud Workload Protection)
| Module | Key | Checks |
|--------|-----|--------|
| GKE / KSPM | `gke` | 9 |
| Serverless | `serverless` | 3 |
| Container Security | `container` | 2 |

### IaC Security
| Module | Key | Checks |
|--------|-----|--------|
| Terraform | `iac` | 2 |

### Compliance & Encryption
| Module | Key | Checks |
|--------|-----|--------|
| CIS Benchmark | `cis` | 1 |
| KMS & Encryption | `kms` | 3 |

## Quick Start
```bash
python gcp_scanner.py --data-dir ./sample_data --output report.html
python gcp_scanner.py --data-dir ./exports --modules iam network gke --severity HIGH
```

### Exporting GCP Configs
```bash
gcloud projects get-iam-policy PROJECT_ID --format=json > iam_policy.json
gcloud compute firewall-rules list --format=json > firewall_rules.json
gcloud compute instances list --format=json > compute_instances.json
gcloud sql instances list --format=json > cloud_sql.json
gcloud container clusters list --format=json > gke_clusters.json
gsutil ls -L -b gs://* 2>/dev/null | ... > storage_buckets.json
```

## References
- CIS GCP Foundation Benchmark v2.0
- GCP Security Best Practices
- NIST SP 800-53
- Wiz / Orca / Sysdig CNAPP Architecture

## License
MIT
