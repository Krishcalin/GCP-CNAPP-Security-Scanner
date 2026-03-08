"""
CSPM Modules 1-4: IAM, Network, Compute, Storage
CIS GCP Foundation Benchmark v2.0 Sections 1-5
"""
from collections import defaultdict
from typing import List, Dict, Any
from modules.base import BaseAuditor

# ═══ Module 1: IAM & Organization Policy (CIS 1.x) ═══
class IamOrgAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_org_admin_sa(); self.check_primitive_roles(); self.check_separation_of_duties()
        self.check_kms_roles(); self.check_sa_admin(); self.check_iam_conditions()
        self.check_domain_restricted(); self.check_essential_contacts()
        return self.findings
    def _bindings(self):
        p=self.data.get("iam_policy")
        if not p: return []
        return p.get("bindings",p) if isinstance(p,dict) else p if isinstance(p,list) else []
    def check_org_admin_sa(self):
        for b in self._bindings():
            role=b.get("role",""); members=b.get("members",[])
            if "admin" in role.lower() or "owner" in role.lower():
                sa_members=[m for m in members if m.startswith("serviceAccount:")]
                if sa_members:
                    self.finding("IAM-001","Service accounts with admin/owner roles",self.SEVERITY_CRITICAL,
                        "IAM & Org Policy","Service accounts should not have Owner or Admin roles.",
                        [f"{m} → {role}" for m in sa_members],
                        "Remove admin/owner roles from service accounts. Use custom roles.",
                        ["CIS GCP 1.5","CIS GCP 1.6"],cis="1.5")
                    break
    def check_primitive_roles(self):
        primitives={"roles/owner":"Owner","roles/editor":"Editor","roles/viewer":"Viewer"}
        issues=[]
        for b in self._bindings():
            role=b.get("role","")
            if role in primitives:
                for m in b.get("members",[]):
                    if not m.startswith("serviceAccount:gcp-sa"): # skip built-in
                        issues.append(f"{m} → {primitives[role]} ({role})")
        if issues:
            self.finding("IAM-002",f"Primitive (basic) roles in use ({len(issues)})",self.SEVERITY_HIGH,
                "IAM & Org Policy","Primitive roles are overly broad. Use predefined/custom roles.",
                issues[:20],"Replace Owner/Editor/Viewer with least-privilege predefined roles.",
                ["CIS GCP 1.4"],cis="1.4")
    def check_separation_of_duties(self):
        user_roles=defaultdict(set)
        for b in self._bindings():
            role=b.get("role","")
            for m in b.get("members",[]):
                if m.startswith("user:"): user_roles[m].add(role)
        conflicts=[]
        sod_pairs=[("roles/iam.serviceAccountAdmin","roles/iam.serviceAccountUser"),
                   ("roles/iam.serviceAccountAdmin","roles/iam.serviceAccountTokenCreator")]
        for u,roles in user_roles.items():
            for a,b_role in sod_pairs:
                if a in roles and b_role in roles:
                    conflicts.append(f"{u}: {a} + {b_role}")
        if conflicts:
            self.finding("IAM-003",f"Separation of duties violations ({len(conflicts)})",self.SEVERITY_HIGH,
                "IAM & Org Policy","Users hold conflicting role combinations.",conflicts,
                "Separate SA Admin from SA User/Token Creator roles.",
                ["CIS GCP 1.8"],cis="1.8")
    def check_kms_roles(self):
        for b in self._bindings():
            role=b.get("role",""); members=b.get("members",[])
            if "cloudkms.admin" in role and "cloudkms.cryptoKeyEncrypterDecrypter" in role:
                pass  # Can't have both in same binding, check across
        kms_admin=set(); kms_crypto=set()
        for b in self._bindings():
            r=b.get("role","")
            if "cloudkms.admin" in r: kms_admin.update(b.get("members",[]))
            if "cryptoKeyEncrypterDecrypter" in r: kms_crypto.update(b.get("members",[]))
        overlap=kms_admin & kms_crypto
        if overlap:
            self.finding("IAM-004","KMS admin and encrypter/decrypter role overlap",self.SEVERITY_HIGH,
                "IAM & Org Policy","Users with both KMS admin and crypto roles can self-approve.",
                list(overlap)[:10],"Separate KMS admin from crypto operations roles.",
                ["CIS GCP 1.11"],cis="1.11")
    def check_sa_admin(self):
        for b in self._bindings():
            role=b.get("role","")
            if "iam.serviceAccountAdmin" in role:
                users=[m for m in b.get("members",[]) if m.startswith("user:")]
                if len(users)>3:
                    self.finding("IAM-005",f"Excessive SA Admin users ({len(users)})",self.SEVERITY_MEDIUM,
                        "IAM & Org Policy","Many users can create/manage service accounts.",
                        users[:10],"Limit SA Admin role.",["CIS GCP 1.6"],cis="1.6")
    def check_iam_conditions(self):
        no_cond=[b.get("role","") for b in self._bindings()
                if not b.get("condition") and "admin" in b.get("role","").lower()]
        if no_cond:
            self.finding("IAM-006","Admin roles without IAM conditions",self.SEVERITY_MEDIUM,
                "IAM & Org Policy","Admin bindings lack time/resource conditions.",
                no_cond[:10],"Add IAM conditions (time-bound, resource-scoped).",
                ["GCP — IAM Conditions Best Practices"])
    def check_domain_restricted(self):
        op=self.data.get("org_policy")
        if not op: return
        constraints=op if isinstance(op,list) else op.get("constraints",op.get("policies",[]))
        has_domain=any("iam.allowedPolicyMemberDomains" in str(c) for c in constraints)
        if not has_domain:
            self.finding("IAM-007","Domain restricted sharing not enforced",self.SEVERITY_HIGH,
                "IAM & Org Policy","IAM bindings can include external identities.",
                remediation="Set iam.allowedPolicyMemberDomains org constraint.",
                references=["CIS GCP 1.1"],cis="1.1")
    def check_essential_contacts(self):
        pc=self.data.get("project_config") or {}
        if isinstance(pc,dict) and not pc.get("essentialContacts",pc.get("contacts",[])):
            self.finding("IAM-008","Essential Contacts not configured",self.SEVERITY_LOW,
                "IAM & Org Policy","No notification contacts for security alerts.",
                remediation="Configure Essential Contacts for Security notifications.",
                references=["CIS GCP 1.16"],cis="1.16")

# ═══ Module 2: Network & VPC Security (CIS 3.x) ═══
class NetworkVpcAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_default_network(); self.check_open_firewall_ssh()
        self.check_open_firewall_rdp(); self.check_firewall_any_any()
        self.check_vpc_flow_logs(); self.check_private_google_access()
        self.check_legacy_networks(); self.check_ssl_proxy()
        return self.findings
    def _firewalls(self):
        d=self.data.get("firewall_rules")
        if not d: return []
        return d if isinstance(d,list) else d.get("rules",d.get("items",[]))
    def check_default_network(self):
        nets=self.data.get("vpc_networks")
        if not nets: return
        nl=nets if isinstance(nets,list) else nets.get("networks",nets.get("items",[]))
        defaults=[n.get("name","") for n in nl if isinstance(n,dict) and n.get("name","")=="default"]
        if defaults:
            self.finding("NET-001","Default VPC network exists",self.SEVERITY_HIGH,
                "Network & VPC","Default network has permissive auto-created firewall rules.",
                defaults,"Delete default VPC. Create custom VPCs with explicit rules.",
                ["CIS GCP 3.1"],cis="3.1")
    def check_open_firewall_ssh(self):
        open_ssh=[]
        for r in self._firewalls():
            if r.get("direction","").upper()!="INGRESS" and r.get("direction","")!="": continue
            if r.get("disabled",False): continue
            src=r.get("sourceRanges",r.get("source_ranges",[]))
            if "0.0.0.0/0" in src:
                for a in r.get("allowed",r.get("allow",[])):
                    ports=a.get("ports",[])
                    if "22" in [str(p) for p in ports] or not ports:
                        open_ssh.append(f"{r.get('name','')}: 0.0.0.0/0 → TCP/22")
        if open_ssh:
            self.finding("NET-002",f"SSH open to internet ({len(open_ssh)} rules)",self.SEVERITY_CRITICAL,
                "Network & VPC","SSH (port 22) accessible from 0.0.0.0/0.",open_ssh,
                "Restrict SSH to specific IP ranges. Use IAP for SSH access.",
                ["CIS GCP 3.6"],cis="3.6")
    def check_open_firewall_rdp(self):
        open_rdp=[]
        for r in self._firewalls():
            if r.get("disabled",False): continue
            src=r.get("sourceRanges",r.get("source_ranges",[]))
            if "0.0.0.0/0" in src:
                for a in r.get("allowed",r.get("allow",[])):
                    ports=a.get("ports",[])
                    if "3389" in [str(p) for p in ports]:
                        open_rdp.append(f"{r.get('name','')}: 0.0.0.0/0 → TCP/3389")
        if open_rdp:
            self.finding("NET-003",f"RDP open to internet ({len(open_rdp)} rules)",self.SEVERITY_CRITICAL,
                "Network & VPC","RDP (3389) accessible from 0.0.0.0/0.",open_rdp,
                "Block RDP from internet. Use IAP tunneling.",
                ["CIS GCP 3.7"],cis="3.7")
    def check_firewall_any_any(self):
        broad=[]
        for r in self._firewalls():
            if r.get("disabled",False): continue
            src=r.get("sourceRanges",[])
            allowed=r.get("allowed",[])
            if "0.0.0.0/0" in src:
                for a in allowed:
                    if not a.get("ports") and a.get("IPProtocol","").lower()=="all":
                        broad.append(f"{r.get('name','')}: 0.0.0.0/0 → ALL protocols/ports")
        if broad:
            self.finding("NET-004",f"Firewall rules allowing all traffic from internet ({len(broad)})",
                self.SEVERITY_CRITICAL,"Network & VPC",
                "Rules allow all protocols/ports from 0.0.0.0/0.",broad,
                "Remove overly permissive rules. Implement least-privilege access.",
                ["CIS GCP 3.8"])
    def check_vpc_flow_logs(self):
        subs=self.data.get("subnets")
        if not subs: return
        sl=subs if isinstance(subs,list) else subs.get("subnets",subs.get("items",[]))
        no_logs=[s.get("name","") for s in sl if isinstance(s,dict)
                and not s.get("logConfig",{}).get("enable",s.get("enableFlowLogs",False))]
        if no_logs:
            self.finding("NET-005",f"Subnets without VPC Flow Logs ({len(no_logs)})",self.SEVERITY_HIGH,
                "Network & VPC","Flow logs provide network monitoring visibility.",no_logs[:15],
                "Enable VPC Flow Logs on all subnets.",["CIS GCP 3.8"],cis="3.8")
    def check_private_google_access(self):
        subs=self.data.get("subnets")
        if not subs: return
        sl=subs if isinstance(subs,list) else subs.get("subnets",subs.get("items",[]))
        no_pga=[s.get("name","") for s in sl if isinstance(s,dict)
               and not s.get("privateIpGoogleAccess",False)]
        if no_pga and len(no_pga)>len(sl)*0.5:
            self.finding("NET-006",f"Subnets without Private Google Access ({len(no_pga)})",self.SEVERITY_MEDIUM,
                "Network & VPC","VMs must use public IPs to reach Google APIs.",no_pga[:10],
                "Enable Private Google Access on all subnets.",["CIS GCP 3.9"],cis="3.9")
    def check_legacy_networks(self):
        nets=self.data.get("vpc_networks")
        if not nets: return
        nl=nets if isinstance(nets,list) else nets.get("networks",nets.get("items",[]))
        legacy=[n.get("name","") for n in nl if isinstance(n,dict)
               and n.get("autoCreateSubnetworks") is None and not n.get("subnetworks")]
        if legacy:
            self.finding("NET-007","Legacy networks detected",self.SEVERITY_HIGH,
                "Network & VPC","Legacy networks don't support modern VPC features.",legacy,
                "Migrate to VPC networks.",["CIS GCP 3.2"],cis="3.2")
    def check_ssl_proxy(self):
        lbs=self.data.get("load_balancers")
        if not lbs: return
        ll=lbs if isinstance(lbs,list) else lbs.get("loadBalancers",[])
        no_ssl=[l.get("name","") for l in ll if isinstance(l,dict)
               and not l.get("sslPolicy") and l.get("protocol","").upper() in ("HTTPS","SSL")]
        if no_ssl:
            self.finding("NET-008","Load balancers without SSL policy",self.SEVERITY_MEDIUM,
                "Network & VPC","No custom SSL policy (may allow weak TLS/ciphers).",no_ssl[:10],
                "Create and attach SSL policy with TLS 1.2+ and strong ciphers.",
                ["CIS GCP 3.9"])

# ═══ Module 3: Compute Engine Security (CIS 4.x) ═══
class ComputeAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_default_sa(); self.check_public_ips()
        self.check_serial_port(); self.check_shielded_vm()
        self.check_os_login(); self.check_disk_encryption()
        return self.findings
    def _instances(self):
        d=self.data.get("compute_instances")
        if not d: return []
        return d if isinstance(d,list) else d.get("instances",d.get("items",[]))
    def check_default_sa(self):
        using_default=[]
        for i in self._instances():
            name=i.get("name","")
            for sa in i.get("serviceAccounts",[]):
                email=sa.get("email","")
                if "compute@developer.gserviceaccount.com" in email:
                    scopes=sa.get("scopes",[])
                    if "https://www.googleapis.com/auth/cloud-platform" in scopes:
                        using_default.append(f"{name}: default SA with full cloud-platform scope")
        if using_default:
            self.finding("COMP-001","VMs using default SA with full scope",self.SEVERITY_CRITICAL,
                "Compute Security","Default compute SA with cloud-platform scope = full project access.",
                using_default[:15],"Create dedicated service accounts with minimal scopes.",
                ["CIS GCP 4.1","CIS GCP 4.2"],cis="4.1")
    def check_public_ips(self):
        public=[]
        for i in self._instances():
            name=i.get("name","")
            for ni in i.get("networkInterfaces",[]):
                for ac in ni.get("accessConfigs",[]):
                    if ac.get("natIP") or ac.get("type")=="ONE_TO_ONE_NAT":
                        public.append(f"{name}: {ac.get('natIP','external IP')}")
        if public:
            self.finding("COMP-002",f"VMs with public IP addresses ({len(public)})",self.SEVERITY_HIGH,
                "Compute Security","VMs directly exposed to internet.",public[:20],
                "Remove external IPs. Use Cloud NAT or IAP for access.",
                ["CIS GCP 4.9","GCP — Private Access Best Practices"],cis="4.9")
    def check_serial_port(self):
        enabled=[]
        for i in self._instances():
            meta=i.get("metadata",{}).get("items",[])
            for m in meta:
                if m.get("key")=="serial-port-enable" and m.get("value","").lower()=="true":
                    enabled.append(i.get("name",""))
        if enabled:
            self.finding("COMP-003","Serial port access enabled on VMs",self.SEVERITY_MEDIUM,
                "Compute Security","Serial port can be used for interactive access.",enabled,
                "Disable serial port: metadata serial-port-enable=false.",
                ["CIS GCP 4.5"],cis="4.5")
    def check_shielded_vm(self):
        not_shielded=[]
        for i in self._instances():
            sc=i.get("shieldedInstanceConfig",{})
            if not sc.get("enableVtpm",False) or not sc.get("enableIntegrityMonitoring",False):
                not_shielded.append(i.get("name",""))
        if not_shielded:
            self.finding("COMP-004",f"VMs without Shielded VM features ({len(not_shielded)})",self.SEVERITY_MEDIUM,
                "Compute Security","Shielded VM provides boot integrity and vTPM.",not_shielded[:15],
                "Enable Shielded VM (vTPM + Integrity Monitoring).",
                ["CIS GCP 4.8"],cis="4.8")
    def check_os_login(self):
        pc=self.data.get("project_config") or {}
        meta=pc.get("commonInstanceMetadata",{}).get("items",[])
        os_login=any(m.get("key")=="enable-oslogin" and m.get("value","").lower()=="true" for m in meta)
        if not os_login and self._instances():
            self.finding("COMP-005","OS Login not enabled project-wide",self.SEVERITY_HIGH,
                "Compute Security","OS Login manages SSH keys centrally via IAM.",
                remediation="Set project metadata: enable-oslogin=TRUE.",
                references=["CIS GCP 4.4"],cis="4.4")
    def check_disk_encryption(self):
        disks=self.data.get("disks")
        if not disks: return
        dl=disks if isinstance(disks,list) else disks.get("disks",disks.get("items",[]))
        no_cmek=[d.get("name","") for d in dl if isinstance(d,dict)
                and not d.get("diskEncryptionKey",{}).get("kmsKeyName")]
        if no_cmek and len(no_cmek)>0:
            self.finding("COMP-006",f"Disks without CMEK encryption ({len(no_cmek)})",self.SEVERITY_MEDIUM,
                "Compute Security","Disks use Google-managed keys instead of CMEK.",no_cmek[:15],
                "Encrypt disks with Customer-Managed Encryption Keys (CMEK).",
                ["CIS GCP 4.7"],cis="4.7")

# ═══ Module 4: Cloud Storage Security (CIS 5.x) ═══
class StorageAuditor(BaseAuditor):
    def run_all_checks(self)->List[Dict]:
        self.check_public_buckets(); self.check_uniform_bucket_access()
        self.check_bucket_logging(); self.check_retention_policy()
        self.check_bucket_encryption()
        return self.findings
    def _buckets(self):
        d=self.data.get("storage_buckets")
        if not d: return []
        return d if isinstance(d,list) else d.get("buckets",d.get("items",[]))
    def check_public_buckets(self):
        public=[]
        for b in self._buckets():
            name=b.get("name","")
            iam=b.get("iamConfiguration",{})
            acl=b.get("acl",b.get("defaultObjectAcl",[]))
            if isinstance(acl,list):
                for a in acl:
                    entity=a.get("entity","")
                    if entity in ("allUsers","allAuthenticatedUsers"):
                        public.append(f"{name}: {entity} access"); break
            bp=self.data.get("bucket_iam")
            if bp and isinstance(bp,dict):
                for bname,policy in bp.items():
                    for bind in policy.get("bindings",[]):
                        if any(m in ("allUsers","allAuthenticatedUsers") for m in bind.get("members",[])):
                            if bname not in [p.split(":")[0] for p in public]:
                                public.append(f"{bname}: {bind.get('role','')} to allUsers")
        if public:
            self.finding("STOR-001","Publicly accessible storage buckets",self.SEVERITY_CRITICAL,
                "Cloud Storage","Buckets exposed to allUsers/allAuthenticatedUsers.",public,
                "Remove allUsers/allAuthenticatedUsers bindings. Use signed URLs for sharing.",
                ["CIS GCP 5.1"],cis="5.1")
    def check_uniform_bucket_access(self):
        non_uniform=[]
        for b in self._buckets():
            ubl=b.get("iamConfiguration",{}).get("uniformBucketLevelAccess",{})
            if not ubl.get("enabled",False):
                non_uniform.append(b.get("name",""))
        if non_uniform:
            self.finding("STOR-002",f"Buckets without Uniform Bucket-Level Access ({len(non_uniform)})",
                self.SEVERITY_HIGH,"Cloud Storage",
                "ACLs and IAM both control access — inconsistent permissions.",non_uniform[:15],
                "Enable Uniform Bucket-Level Access on all buckets.",
                ["CIS GCP 5.2"],cis="5.2")
    def check_bucket_logging(self):
        no_log=[b.get("name","") for b in self._buckets()
               if isinstance(b,dict) and not b.get("logging",{}).get("logBucket")]
        if no_log:
            self.finding("STOR-003",f"Buckets without access logging ({len(no_log)})",self.SEVERITY_MEDIUM,
                "Cloud Storage","Bucket access not being logged.",no_log[:15],
                "Enable access logging: gsutil logging set on gs://bucket.",
                ["CIS GCP 5.3"])
    def check_retention_policy(self):
        no_ret=[b.get("name","") for b in self._buckets()
               if isinstance(b,dict) and not b.get("retentionPolicy")]
        if no_ret and len(no_ret)>len(self._buckets())*0.5:
            self.finding("STOR-004","Buckets without retention policies",self.SEVERITY_LOW,
                "Cloud Storage","No data retention/lifecycle policies.",no_ret[:10],
                "Set retention policies for compliance.",["GCP — Bucket Lifecycle"])
    def check_bucket_encryption(self):
        no_cmek=[b.get("name","") for b in self._buckets()
                if isinstance(b,dict) and not b.get("encryption",{}).get("defaultKmsKeyName")]
        if no_cmek:
            self.finding("STOR-005",f"Buckets without CMEK encryption ({len(no_cmek)})",self.SEVERITY_MEDIUM,
                "Cloud Storage","Buckets use Google-managed keys.",no_cmek[:10],
                "Set default CMEK encryption on buckets.",["CIS GCP 5.3"])
