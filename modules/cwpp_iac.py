"""
CWPP Modules 10-12 + IaC Module 13 + Compliance 14-15
GKE, Serverless, Container, Terraform, CIS, KMS
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 10: GKE / Kubernetes Security (KSPM) ═══
class GkeSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_gke_exists(); self.check_legacy_abac(); self.check_network_policy()
        self.check_private_cluster(); self.check_workload_identity()
        self.check_shielded_nodes(); self.check_binary_auth()
        self.check_master_auth(); self.check_node_auto_upgrade()
        return self.findings
    def _clusters(self):
        d=self.data.get("gke_clusters")
        if not d: return []
        return d if isinstance(d,list) else d.get("clusters",[])
    def check_gke_exists(self):
        if not self._clusters(): return  # GKE not in use
    def check_legacy_abac(self):
        for c in self._clusters():
            if not isinstance(c,dict): continue
            if c.get("legacyAbac",{}).get("enabled",False):
                self.finding("GKE-001",f"GKE cluster '{c.get('name','')}' has legacy ABAC enabled",
                    self.SEVERITY_HIGH,"GKE Security","Legacy ABAC bypasses RBAC controls.",
                    [c.get("name","")],"Disable legacy ABAC. Use RBAC only.",
                    ["CIS GKE 5.8.1"],cis="GKE 5.8.1")
    def check_network_policy(self):
        no_np=[c.get("name","") for c in self._clusters()
              if isinstance(c,dict) and not c.get("networkPolicy",{}).get("enabled",False)
              and not c.get("addonsConfig",{}).get("networkPolicyConfig",{}).get("disabled") is False]
        if no_np:
            self.finding("GKE-002",f"GKE clusters without Network Policy ({len(no_np)})",self.SEVERITY_HIGH,
                "GKE Security","No pod-to-pod network segmentation.",no_np,
                "Enable Network Policy (Calico) on all clusters.",
                ["CIS GKE 5.6.7"])
    def check_private_cluster(self):
        public=[c.get("name","") for c in self._clusters()
               if isinstance(c,dict) and not c.get("privateClusterConfig",{}).get("enablePrivateNodes",False)]
        if public:
            self.finding("GKE-003",f"GKE clusters with public nodes ({len(public)})",self.SEVERITY_HIGH,
                "GKE Security","Nodes have public IPs, exposed to internet.",public,
                "Enable Private Cluster (private nodes + private endpoint).",
                ["CIS GKE 5.4.1"])
    def check_workload_identity(self):
        no_wi=[c.get("name","") for c in self._clusters()
              if isinstance(c,dict) and not c.get("workloadIdentityConfig",{}).get("workloadPool")]
        if no_wi:
            self.finding("GKE-004",f"GKE clusters without Workload Identity ({len(no_wi)})",self.SEVERITY_HIGH,
                "GKE Security","Pods may use node SA instead of per-pod identity.",no_wi,
                "Enable Workload Identity for per-pod IAM binding.",
                ["CIS GKE 5.2.1","GCP — Workload Identity"])
    def check_shielded_nodes(self):
        no_shielded=[c.get("name","") for c in self._clusters()
                    if isinstance(c,dict) and not c.get("shieldedNodes",{}).get("enabled",False)]
        if no_shielded:
            self.finding("GKE-005",f"GKE clusters without Shielded GKE Nodes ({len(no_shielded)})",
                self.SEVERITY_MEDIUM,"GKE Security","Nodes lack integrity verification.",no_shielded,
                "Enable Shielded GKE Nodes.",["CIS GKE 5.5.1"])
    def check_binary_auth(self):
        no_ba=[c.get("name","") for c in self._clusters()
              if isinstance(c,dict) and not c.get("binaryAuthorization",{}).get("enabled",False)]
        if no_ba:
            self.finding("GKE-006",f"Binary Authorization not enabled ({len(no_ba)})",self.SEVERITY_MEDIUM,
                "GKE Security","Unsigned/unverified container images can be deployed.",no_ba,
                "Enable Binary Authorization for image signing verification.",
                ["CIS GKE 5.9.1","GCP — Binary Authorization"])
    def check_master_auth(self):
        for c in self._clusters():
            if not isinstance(c,dict): continue
            ma=c.get("masterAuth",{})
            if ma.get("username") or ma.get("password"):
                self.finding("GKE-007",f"GKE cluster '{c.get('name','')}' uses basic authentication",
                    self.SEVERITY_CRITICAL,"GKE Security","Basic auth (username/password) for API server.",
                    [c.get("name","")],"Disable basic auth. Use IAM/OIDC.",
                    ["CIS GKE 5.1.1"],cis="GKE 5.1.1"); break
    def check_node_auto_upgrade(self):
        no_upgrade=[]
        for c in self._clusters():
            if not isinstance(c,dict): continue
            for np in c.get("nodePools",[]):
                if not np.get("management",{}).get("autoUpgrade",False):
                    no_upgrade.append(f"{c.get('name','')}/{np.get('name','')}")
        if no_upgrade:
            self.finding("GKE-008",f"GKE node pools without auto-upgrade ({len(no_upgrade)})",self.SEVERITY_MEDIUM,
                "GKE Security","Nodes may run outdated/vulnerable versions.",no_upgrade[:10],
                "Enable node auto-upgrade.",["CIS GKE 5.5.3"])

# ═══ Module 11: Cloud Functions / Serverless ═══
class ServerlessAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_function_permissions(); self.check_function_ingress()
        self.check_function_sa()
        return self.findings
    def _functions(self):
        d=self.data.get("cloud_functions")
        if not d: return []
        return d if isinstance(d,list) else d.get("functions",[])
    def check_function_permissions(self):
        public=[]
        for f in self._functions():
            if not isinstance(f,dict): continue
            invoker=f.get("invoker",f.get("httpsTrigger",{}).get("securityLevel",""))
            iam=f.get("iamBindings",[])
            for b in iam:
                if "allUsers" in b.get("members",[]):
                    public.append(f"{f.get('name','')}: allUsers invoker")
        if public:
            self.finding("FN-001","Cloud Functions publicly invocable",self.SEVERITY_HIGH,
                "Serverless Security","Functions callable by anyone on internet.",public,
                "Remove allUsers. Require authentication for function invocation.",
                ["GCP — Cloud Functions IAM"])
    def check_function_ingress(self):
        open_fn=[f.get("name","") for f in self._functions()
                if isinstance(f,dict) and f.get("ingressSettings","").upper()=="ALLOW_ALL"]
        if open_fn:
            self.finding("FN-002",f"Functions with ALLOW_ALL ingress ({len(open_fn)})",self.SEVERITY_MEDIUM,
                "Serverless Security","Functions accept traffic from any source.",open_fn[:10],
                "Set ingress to ALLOW_INTERNAL_ONLY or ALLOW_INTERNAL_AND_GCLB.",
                ["GCP — Cloud Functions Networking"])
    def check_function_sa(self):
        default_sa=[f.get("name","") for f in self._functions()
                   if isinstance(f,dict) and "appspot.gserviceaccount.com" in f.get("serviceAccountEmail","")]
        if default_sa:
            self.finding("FN-003",f"Functions using default App Engine SA ({len(default_sa)})",self.SEVERITY_HIGH,
                "Serverless Security","Default SA has Editor role on project.",default_sa[:10],
                "Create dedicated per-function service accounts with minimal roles.",
                ["GCP — Cloud Functions Identity"])

# ═══ Module 12: Container Security ═══
class ContainerSecurityAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_container_analysis(); self.check_artifact_registry()
        return self.findings
    def check_container_analysis(self):
        apis=self.data.get("apis_enabled")
        if apis and isinstance(apis,list):
            api_names=[a.get("config",{}).get("name",a.get("name","")) if isinstance(a,dict) else str(a) for a in apis]
            if not any("containeranalysis" in str(a).lower() or "containerscanning" in str(a).lower() for a in api_names):
                self.finding("CONT-001","Container Analysis API not enabled",self.SEVERITY_MEDIUM,
                    "Container Security","No automated vulnerability scanning for container images.",
                    remediation="Enable Container Analysis and Container Scanning APIs.",
                    references=["GCP — Container Analysis"])
    def check_artifact_registry(self):
        images=self.data.get("container_images")
        if not images: return
        il=images if isinstance(images,list) else images.get("images",[])
        gcr=[i.get("name","") for i in il if isinstance(i,dict) and "gcr.io" in i.get("uri",i.get("name",""))]
        if gcr:
            self.finding("CONT-002","Images in legacy Container Registry (gcr.io)",self.SEVERITY_LOW,
                "Container Security","gcr.io is legacy. Artifact Registry is recommended.",
                gcr[:10],"Migrate to Artifact Registry.",["GCP — Artifact Registry Migration"])

# ═══ Module 13: IaC Security (Terraform) ═══
class IacSecurityAuditor(BaseAuditor):
    RISKY_PATTERNS={
        "0.0.0.0/0":("Network","Firewall rule allows all IPs"),
        "allUsers":("IAM","Resource accessible by allUsers"),
        "allAuthenticatedUsers":("IAM","Resource accessible by allAuthenticatedUsers"),
        "cloud-platform":("IAM","Full cloud-platform scope"),
        "CMEK":None,  # Absence check
        "enable_legacy_abac\":true":("GKE","Legacy ABAC enabled"),
        "require_ssl\":false":("Database","SSL not required"),
        "enable_private_nodes\":false":("GKE","Public nodes enabled"),
    }
    def run_all_checks(self)->List[Dict]:
        self.check_tfstate_misconfigs(); self.check_tfplan_risks()
        return self.findings
    def check_tfstate_misconfigs(self):
        state=self.data.get("terraform_state")
        if not state: return
        raw=str(state)
        issues=[]
        for pattern,(cat,desc) in [(k,v) for k,v in self.RISKY_PATTERNS.items() if v]:
            if pattern in raw:
                count=raw.count(pattern)
                issues.append(f"[{cat}] {desc} — found {count} occurrence(s)")
        if issues:
            self.finding("IAC-001",f"Terraform state misconfigurations ({len(issues)})",self.SEVERITY_HIGH,
                "IaC Security","Terraform state contains risky configurations.",issues[:20],
                "Review and remediate Terraform configs. Run `terraform plan` to validate.",
                ["CIS GCP — IaC Best Practices","Terraform — GCP Security"])
    def check_tfplan_risks(self):
        plan=self.data.get("terraform_plan")
        if not plan: return
        changes=plan.get("resource_changes",plan.get("planned_values",{}).get("root_module",{}).get("resources",[]))
        destroys=[r.get("address","") for r in changes
                 if isinstance(r,dict) and "delete" in str(r.get("change",{}).get("actions",[]))]
        if destroys:
            self.finding("IAC-002",f"Terraform plan includes resource deletions ({len(destroys)})",self.SEVERITY_MEDIUM,
                "IaC Security","Plan will destroy resources — verify intent.",destroys[:15],
                "Review terraform plan output before applying.",
                ["Terraform — Plan Review Best Practices"])

# ═══ Module 14: CIS Benchmark Compliance Summary ═══
class CisBenchmarkAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        # This module summarizes CIS findings from other modules — meta-check
        self.check_cis_coverage()
        return self.findings
    def check_cis_coverage(self):
        # Just a summary finding
        self.finding("CIS-001","CIS GCP Foundation Benchmark v2.0 assessment complete",self.SEVERITY_LOW,
            "CIS Benchmark","Checks mapped to CIS GCP Foundation Benchmark sections 1-7.",
            remediation="Review individual findings for CIS section references.",
            references=["CIS GCP Foundation Benchmark v2.0"],
            details={"sections_covered":"1.x IAM, 2.x Logging, 3.x Networking, 4.x Compute, 5.x Storage, 6.x SQL, 7.x BigQuery"})

# ═══ Module 15: KMS & Encryption ═══
class KmsEncryptionAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_kms_rotation(); self.check_kms_iam()
        self.check_kms_separation()
        return self.findings
    def check_kms_rotation(self):
        keys=self.data.get("kms_keys")
        if not keys: return
        kl=keys if isinstance(keys,list) else keys.get("cryptoKeys",[])
        no_rotation=[k.get("name","").split("/")[-1] for k in kl
                    if isinstance(k,dict) and not k.get("rotationPeriod")]
        if no_rotation:
            self.finding("KMS-001",f"KMS keys without rotation period ({len(no_rotation)})",self.SEVERITY_HIGH,
                "KMS & Encryption","Keys not automatically rotated.",no_rotation[:15],
                "Set rotation period ≤365 days on all KMS keys.",
                ["CIS GCP 1.10"],cis="1.10")
    def check_kms_iam(self):
        keys=self.data.get("kms_keys")
        if not keys: return
        kl=keys if isinstance(keys,list) else keys.get("cryptoKeys",[])
        public_keys=[k.get("name","").split("/")[-1] for k in kl
                    if isinstance(k,dict) and any("allUsers" in str(b) or "allAuthenticatedUsers" in str(b)
                    for b in k.get("iamBindings",k.get("bindings",[])))]
        if public_keys:
            self.finding("KMS-002","KMS keys with public access",self.SEVERITY_CRITICAL,
                "KMS & Encryption","Encryption keys accessible by allUsers.",public_keys,
                "Remove public access from KMS keys immediately.",
                ["CIS GCP 1.9"],cis="1.9")
    def check_kms_separation(self):
        # Check if same identity has both admin and encrypt/decrypt
        keys=self.data.get("kms_keys")
        if not keys: return
        kl=keys if isinstance(keys,list) else keys.get("cryptoKeys",[])
        for k in kl:
            if not isinstance(k,dict): continue
            admins=set(); crypto=set()
            for b in k.get("iamBindings",k.get("bindings",[])):
                r=b.get("role","")
                if "admin" in r.lower(): admins.update(b.get("members",[]))
                if "encrypterDecrypter" in r or "decrypter" in r: crypto.update(b.get("members",[]))
            overlap=admins & crypto
            if overlap:
                self.finding("KMS-003","KMS key admin and crypto role overlap",self.SEVERITY_HIGH,
                    "KMS & Encryption","Same identity has admin + encrypt/decrypt on key.",
                    list(overlap)[:5],"Separate KMS admin from crypto operations.",
                    ["CIS GCP 1.11"],cis="1.11"); break
