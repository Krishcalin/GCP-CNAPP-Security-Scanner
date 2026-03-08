"""
CSPM Modules 5-7 + CIEM Modules 8-9
Database, Logging, BigQuery, IAM Entitlements, Service Accounts
"""
from datetime import datetime
from collections import defaultdict
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 5: Cloud SQL & Database (CIS 6.x) ═══
class DatabaseAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_sql_public_ip(); self.check_sql_ssl()
        self.check_sql_auth_networks(); self.check_sql_backups()
        self.check_sql_flags()
        return self.findings
    def _sql(self):
        d=self.data.get("cloud_sql")
        if not d: return []
        return d if isinstance(d,list) else d.get("instances",d.get("items",[]))
    def check_sql_public_ip(self):
        public=[i.get("name","") for i in self._sql()
               if isinstance(i,dict) and any(a.get("type")=="PRIMARY" and a.get("ipAddress")
               for a in i.get("ipAddresses",[]))]
        if public:
            self.finding("DB-001",f"Cloud SQL instances with public IPs ({len(public)})",self.SEVERITY_HIGH,
                "Cloud SQL","SQL instances directly accessible from internet.",public,
                "Use private IP only. Remove public IP. Connect via Cloud SQL Proxy.",
                ["CIS GCP 6.5"],cis="6.5")
    def check_sql_ssl(self):
        no_ssl=[i.get("name","") for i in self._sql()
               if isinstance(i,dict) and not i.get("settings",{}).get("ipConfiguration",{}).get("requireSsl",False)]
        if no_ssl:
            self.finding("DB-002",f"Cloud SQL without SSL enforcement ({len(no_ssl)})",self.SEVERITY_HIGH,
                "Cloud SQL","Unencrypted database connections allowed.",no_ssl,
                "Set requireSsl=true on all SQL instances.",["CIS GCP 6.4"],cis="6.4")
    def check_sql_auth_networks(self):
        broad=[]
        for i in self._sql():
            if not isinstance(i,dict): continue
            nets=i.get("settings",{}).get("ipConfiguration",{}).get("authorizedNetworks",[])
            for n in nets:
                if n.get("value") in ("0.0.0.0/0","::/0"):
                    broad.append(f"{i.get('name','')}: authorized={n.get('value')}")
        if broad:
            self.finding("DB-003","Cloud SQL authorized networks include 0.0.0.0/0",self.SEVERITY_CRITICAL,
                "Cloud SQL","Database accessible from any IP.",broad,
                "Remove 0.0.0.0/0. Use specific CIDR ranges or private IP.",
                ["CIS GCP 6.5"],cis="6.5")
    def check_sql_backups(self):
        no_backup=[i.get("name","") for i in self._sql()
                  if isinstance(i,dict) and not i.get("settings",{}).get("backupConfiguration",{}).get("enabled",False)]
        if no_backup:
            self.finding("DB-004",f"Cloud SQL without automated backups ({len(no_backup)})",self.SEVERITY_HIGH,
                "Cloud SQL","No automated backups configured.",no_backup,
                "Enable automated backups with point-in-time recovery.",
                ["CIS GCP 6.7"],cis="6.7")
    def check_sql_flags(self):
        issues=[]
        for i in self._sql():
            if not isinstance(i,dict): continue
            name=i.get("name",""); flags=i.get("settings",{}).get("databaseFlags",[])
            flag_dict={f.get("name",""):f.get("value","") for f in flags}
            db_type=i.get("databaseVersion","").upper()
            if "POSTGRES" in db_type:
                if flag_dict.get("log_checkpoints")!="on": issues.append(f"{name}: log_checkpoints not on")
                if flag_dict.get("log_connections")!="on": issues.append(f"{name}: log_connections not on")
            if "MYSQL" in db_type:
                if flag_dict.get("local_infile")!="off": issues.append(f"{name}: local_infile not disabled")
        if issues:
            self.finding("DB-005",f"Cloud SQL security flags not set ({len(issues)})",self.SEVERITY_MEDIUM,
                "Cloud SQL","Database security flags missing.",issues[:15],
                "Set recommended database flags per CIS benchmark.",
                ["CIS GCP 6.1-6.3"],cis="6.1")

# ═══ Module 6: Logging & Monitoring (CIS 2.x) ═══
class LoggingMonitoringAuditor(BaseAuditor):
    REQUIRED_METRICS=["IAM changes","Audit config changes","Custom role changes",
        "Firewall rule changes","Network route changes","Storage IAM changes",
        "SQL config changes","Project ownership changes"]
    def run_all_checks(self)->List[Dict]:
        self.check_audit_logging(); self.check_log_sinks()
        self.check_log_metrics(); self.check_alert_policies()
        self.check_retention()
        return self.findings
    def check_audit_logging(self):
        ac=self.data.get("audit_config")
        if not ac:
            self.finding("LOG-001","Audit logging configuration not found",self.SEVERITY_HIGH,
                "Logging & Monitoring","Cannot verify Cloud Audit Logs config.",
                remediation="Enable Data Access audit logs for all services.",
                references=["CIS GCP 2.1"],cis="2.1")
            return
        cfg=ac if isinstance(ac,dict) else {}
        services=cfg.get("auditConfigs",cfg.get("services",[]))
        if not services or len(services)<3:
            self.finding("LOG-002","Insufficient audit logging coverage",self.SEVERITY_HIGH,
                "Logging & Monitoring","Data Access logs not enabled for all services.",
                remediation="Enable DATA_READ and DATA_WRITE audit logs.",
                references=["CIS GCP 2.1"],cis="2.1")
    def check_log_sinks(self):
        sinks=self.data.get("log_sinks")
        if not sinks:
            self.finding("LOG-003","No log sinks (exports) configured",self.SEVERITY_HIGH,
                "Logging & Monitoring","Logs not exported to external storage/SIEM.",
                remediation="Create log sinks to BigQuery, Cloud Storage, or Pub/Sub.",
                references=["CIS GCP 2.2"],cis="2.2")
    def check_log_metrics(self):
        metrics=self.data.get("log_metrics")
        if not metrics:
            self.finding("LOG-004","No log-based metrics configured",self.SEVERITY_HIGH,
                "Logging & Monitoring","No metrics for critical security events.",
                remediation="Create log metrics for IAM changes, firewall changes, etc.",
                references=["CIS GCP 2.4-2.11"],cis="2.4")
    def check_alert_policies(self):
        alerts=self.data.get("alert_policies")
        if not alerts:
            self.finding("LOG-005","No alerting policies configured",self.SEVERITY_HIGH,
                "Logging & Monitoring","No alerts for security events.",
                remediation="Create alert policies on log-based metrics.",
                references=["CIS GCP 2.4-2.11"],cis="2.4")
    def check_retention(self):
        sinks=self.data.get("log_sinks")
        if sinks and isinstance(sinks,list):
            for s in sinks:
                if isinstance(s,dict) and s.get("retentionDays",0)<365:
                    self.finding("LOG-006",f"Log retention below 365 days",self.SEVERITY_MEDIUM,
                        "Logging & Monitoring","Short log retention for compliance.",
                        remediation="Set retention ≥365 days.",references=["CIS GCP 2.3"]); break

# ═══ Module 7: BigQuery Security ═══
class BigQueryAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_dataset_access(); self.check_cmek_encryption()
        return self.findings
    def check_dataset_access(self):
        ds=self.data.get("bigquery_datasets")
        if not ds: return
        dl=ds if isinstance(ds,list) else ds.get("datasets",[])
        public=[]
        for d in dl:
            if not isinstance(d,dict): continue
            for a in d.get("access",[]):
                if a.get("specialGroup") in ("allAuthenticatedUsers","projectWriters"):
                    public.append(f"{d.get('datasetReference',{}).get('datasetId','')}: {a.get('specialGroup')}")
        if public:
            self.finding("BQ-001","BigQuery datasets with broad access",self.SEVERITY_HIGH,
                "BigQuery","Datasets accessible to allAuthenticatedUsers.",public,
                "Remove allAuthenticatedUsers. Grant specific roles.",
                ["CIS GCP 7.1"],cis="7.1")
    def check_cmek_encryption(self):
        ds=self.data.get("bigquery_datasets")
        if not ds: return
        dl=ds if isinstance(ds,list) else ds.get("datasets",[])
        no_cmek=[d.get("datasetReference",{}).get("datasetId","") for d in dl
                if isinstance(d,dict) and not d.get("defaultEncryptionConfiguration",{}).get("kmsKeyName")]
        if no_cmek:
            self.finding("BQ-002",f"BigQuery datasets without CMEK ({len(no_cmek)})",self.SEVERITY_MEDIUM,
                "BigQuery","Datasets use Google-managed encryption.",no_cmek[:10],
                "Set CMEK on BigQuery datasets.",["CIS GCP 7.2"],cis="7.2")

# ═══ Module 8: CIEM — IAM Entitlements (Least Privilege) ═══
class CiemEntitlementsAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_overprivileged_users(); self.check_unused_roles()
        self.check_external_identities(); self.check_allUsers_bindings()
        return self.findings
    def _bindings(self):
        p=self.data.get("iam_policy")
        if not p: return []
        return p.get("bindings",p) if isinstance(p,dict) else p if isinstance(p,list) else []
    def check_overprivileged_users(self):
        user_roles=defaultdict(set)
        for b in self._bindings():
            r=b.get("role","")
            for m in b.get("members",[]):
                if m.startswith("user:"): user_roles[m].add(r)
        over=[f"{u}: {len(roles)} roles" for u,roles in user_roles.items() if len(roles)>10]
        if over:
            self.finding("CIEM-001",f"Users with excessive role assignments ({len(over)})",self.SEVERITY_HIGH,
                "CIEM Entitlements","Users with >10 roles likely have excessive privileges.",over[:15],
                "Review and consolidate role assignments. Apply least privilege.",
                ["GCP — IAM Best Practices","CIEM — Privilege Right-Sizing"])
    def check_unused_roles(self):
        # Heuristic — look for roles that seem like leftovers
        custom_roles=[b.get("role","") for b in self._bindings()
                     if b.get("role","").startswith("projects/")]
        if custom_roles:
            self.finding("CIEM-002","Custom roles detected — review for least privilege",self.SEVERITY_LOW,
                "CIEM Entitlements",f"{len(set(custom_roles))} custom roles in use.",
                list(set(custom_roles))[:10],
                "Review custom roles with IAM Recommender. Remove unused permissions.",
                ["GCP — IAM Recommender"])
    def check_external_identities(self):
        external=[]
        for b in self._bindings():
            for m in b.get("members",[]):
                if m.startswith("user:") and "@gmail.com" in m:
                    external.append(f"{m} → {b.get('role','')}")
        if external:
            self.finding("CIEM-003",f"Gmail (external) accounts with IAM access ({len(external)})",
                self.SEVERITY_HIGH,"CIEM Entitlements",
                "Non-organizational (@gmail.com) identities have project access.",external[:15],
                "Remove external identities. Use organization domain accounts only.",
                ["CIS GCP 1.1"],cis="1.1")
    def check_allUsers_bindings(self):
        public=[]
        for b in self._bindings():
            if "allUsers" in b.get("members",[]) or "allAuthenticatedUsers" in b.get("members",[]):
                public.append(f"{b.get('role','')}: allUsers/allAuthenticatedUsers")
        if public:
            self.finding("CIEM-004","Project-level allUsers/allAuthenticatedUsers bindings",self.SEVERITY_CRITICAL,
                "CIEM Entitlements","Project resources exposed publicly.",public,
                "Remove allUsers/allAuthenticatedUsers from project IAM.",
                ["CIS GCP 1.2"])

# ═══ Module 9: CIEM — Service Account Security ═══
class ServiceAccountAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_sa_key_rotation(); self.check_sa_key_types()
        self.check_unused_sa(); self.check_sa_impersonation()
        return self.findings
    def check_sa_key_rotation(self):
        keys=self.data.get("sa_keys")
        if not keys: return
        kl=keys if isinstance(keys,list) else keys.get("keys",[])
        old=[]
        for k in kl:
            if not isinstance(k,dict): continue
            if k.get("keyType","")=="USER_MANAGED":
                created=k.get("validAfterTime",k.get("createTime",""))
                if created:
                    try:
                        d=datetime.strptime(created[:19],"%Y-%m-%dT%H:%M:%S")
                        age=(datetime.now()-d).days
                        if age>90: old.append(f"{k.get('name','').split('/')[-1][:20]}...: {age}d old")
                    except ValueError: pass
        if old:
            self.finding("SA-001",f"Service account keys older than 90 days ({len(old)})",self.SEVERITY_HIGH,
                "Service Account Security","SA keys should be rotated every 90 days.",old[:15],
                "Rotate or delete old SA keys. Use Workload Identity where possible.",
                ["CIS GCP 1.7"],cis="1.7")
    def check_sa_key_types(self):
        keys=self.data.get("sa_keys")
        if not keys: return
        kl=keys if isinstance(keys,list) else keys.get("keys",[])
        user_managed=[k for k in kl if isinstance(k,dict) and k.get("keyType")=="USER_MANAGED"]
        if user_managed:
            self.finding("SA-002",f"User-managed SA keys exist ({len(user_managed)})",self.SEVERITY_MEDIUM,
                "Service Account Security","User-managed keys are high risk — prefer Workload Identity.",
                [f"Key: {k.get('name','')[-30:]}" for k in user_managed[:10]],
                "Migrate to Workload Identity Federation. Delete user-managed keys.",
                ["CIS GCP 1.4","GCP — Workload Identity"])
    def check_unused_sa(self):
        sas=self.data.get("service_accounts")
        if not sas: return
        sl=sas if isinstance(sas,list) else sas.get("accounts",[])
        disabled=[sa.get("email","") for sa in sl if isinstance(sa,dict) and sa.get("disabled",False)]
        if disabled:
            self.finding("SA-003",f"Disabled service accounts still exist ({len(disabled)})",self.SEVERITY_LOW,
                "Service Account Security","Disabled SAs should be cleaned up.",disabled[:10],
                "Delete disabled service accounts.",["GCP — SA Lifecycle"])
    def check_sa_impersonation(self):
        for b in (self.data.get("iam_policy",{}).get("bindings",[])
                 if isinstance(self.data.get("iam_policy"),dict) else []):
            if "iam.serviceAccountTokenCreator" in b.get("role",""):
                users=[m for m in b.get("members",[]) if m.startswith("user:")]
                if len(users)>3:
                    self.finding("SA-004",f"Many users can impersonate service accounts ({len(users)})",
                        self.SEVERITY_HIGH,"Service Account Security",
                        "SA Token Creator enables impersonation of any SA.",users[:10],
                        "Restrict Token Creator role. Use conditional bindings.",
                        ["CIS GCP 1.6"])
