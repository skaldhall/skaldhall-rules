# Bragi detection catalog — triggers & expected results

How to fire every rule, and what you should see when it works. Two producers emit
Kubernetes API activity (OCSF class 6003) and nest the resource differently, so
rules match both shapes:

- **audit** — the kube-apiserver audit source; carries the **actor** (`actor.user.name`)
  and the request path. This is the shape that names *who* did it.
- **watch** — the operator's state-watch inventory; carries a computed
  `summary.*` security digest but **no actor** (a state diff sees *what*, never *who*).

**Expected result, unless noted:** within ~1 min a Security-Analytics finding is
raised; within ~2 more min it is mirrored into `ocsf-detection-finding` (OCSF 2004)
at the listed severity and appears on the Events page. The raw 6003/runtime record
itself stays informational — severity lives on the finding.

**Verification status (dev, 2026-07-21):** every rule below was confirmed to match a
crafted triggering document via its live compiled detector query. Runtime (Tetragon)
rules were verified at the rule layer by injecting the post-parse OCSF record;
the eBPF→record layer (the TracingPolicies) needs a real cluster with Tetragon and is
called out under "Runtime prerequisites".

---

## Kubernetes API rules (class 6003)

### A. Workload hardening — matched from the `summary.*` digest (watch shape)

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Privileged pod created or modified | **critical** | `kubectl run p --image=nginx --privileged` (or any pod with `securityContext.privileged: true`) | finding "Privileged pod created or modified" |
| Pod mounts a sensitive host path | **critical** | create a pod with a `hostPath` volume on `/etc`, `/proc`, `/var/lib/kubelet`, `/root`, `/boot`, or a container-runtime socket | finding "Pod mounts a sensitive host path" |
| Pod mounts a host path | **high** | create a pod with any `hostPath` volume (e.g. `/opt/data`) | finding "Pod mounts a host path" (sensitive paths additionally raise the critical one) |
| Pod shares a host namespace | **high** | pod with `hostNetwork`, `hostPID` **or** `hostIPC: true` | finding "Pod shares a host namespace" |
| Pod adds a dangerous Linux capability | **high** | pod adding `SYS_ADMIN`/`SYS_PTRACE`/`SYS_MODULE`/`NET_ADMIN`/`BPF`/`SYS_RAWIO`/`SYS_BOOT`/`DAC_READ_SEARCH` | finding "Pod adds a dangerous Linux capability" |
| Pod may run as root outside system namespaces | **medium** | pod in a non-`kube-*` namespace with no `runAsNonRoot`/`runAsUser` assertion | finding "Pod may run as root…"; heavy whitelist expected day one |
| Pod uses an image from a public registry | **medium** | pod whose image is `docker.io/…`, `ghcr.io/…`, `quay.io/…`, `gcr.io/…`, `public.ecr.aws`, `registry.k8s.io` | finding "Pod uses an image from a public registry". Bare names (implicit docker.io) are **not** caught — enforce an internal-registry naming convention |
| Static pod appeared | **high** | place a manifest in the kubelet's `staticPodPath` (pod ends up owned by a Node) | finding "Static pod appeared" |

### B. Identity & RBAC (audit shape unless noted)

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Binding grants the system:masters group | **critical** | create a ClusterRoleBinding with a subject `kind: Group, name: system:masters` | finding "Binding grants the system:masters group" |
| Binding to cluster-admin created or changed | **high** | `kubectl create clusterrolebinding x --clusterrole=cluster-admin --user=bob` | finding "Binding to cluster-admin created or changed" |
| ClusterRoleBinding created, changed or deleted | **medium** | create/modify/delete any other ClusterRoleBinding | finding "ClusterRoleBinding created, changed or deleted" (CD tooling whitelisted by actor) |
| RBAC changed in kube-system | **high** | create/modify/delete a Role or RoleBinding in `kube-system` | finding "RBAC changed in kube-system" |
| ServiceAccount created | **medium** | `kubectl create sa foo -n app` | finding "ServiceAccount created" |
| ServiceAccount created in kube-system | **high** | `kubectl create sa foo -n kube-system` | finding "ServiceAccount created in kube-system" |
| ServiceAccount API token requested | **medium** | `kubectl create token foo` (TokenRequest) | finding "ServiceAccount API token requested"; kubelet/controllers (system:*) whitelisted |
| Legacy service-account-token Secret created | **high** | create a `Secret` of type `kubernetes.io/service-account-token` (needs audit at Request level) | finding "Legacy service-account-token Secret created" |
| CertificateSigningRequest approved | **high** | `kubectl certificate approve <csr>` | finding "CertificateSigningRequest approved" (kube-controller-manager auto-approvals whitelisted) |
| Anonymous API request succeeded | **critical** | any 2xx response to a `system:anonymous` request (a real hit means unauthenticated access is possible) | finding "Anonymous API request succeeded" — investigate immediately |
| Anonymous API request denied | **medium** | an external scanner hitting the API server (401/403 as `system:anonymous`) | finding "Anonymous API request denied" |
| Secrets listed or bulk-deleted by a user | **high** | `kubectl get secrets -n app` (list) or a deletecollection, under a non-system identity | finding "Secrets listed or bulk-deleted by a user" |
| Workload enumerated its own permissions | **high** | a **service account** issuing a SelfSubjectAccessReview / `auth can-i` from inside a pod | finding "Workload enumerated its own permissions"; humans excluded |
| API request used impersonation | **high** | `kubectl --as=someone get …` (needs the audit VRL's `actor.impersonated_user`, shipped with this release) | finding "API request used impersonation"; break-glass admin whitelisted |

### C. Control-plane & admission (audit shape unless noted)

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Admission webhook configuration created or deleted | **high** | create or delete a Mutating/ValidatingWebhookConfiguration | finding "Admission webhook configuration created or deleted" |
| Admission webhook configuration modified | **medium** | patch a webhook configuration | finding "Admission webhook configuration modified" (cert-manager cainjector whitelisted) |
| Critical system ConfigMap changed | **critical** | modify/delete the `coredns`, `aws-auth`, `kube-proxy`, or `extension-apiserver-authentication` ConfigMap | finding "Critical system ConfigMap changed" |
| kube-system ConfigMap changed by a user | **high** | any ConfigMap write in `kube-system` by a non-system principal | finding "kube-system ConfigMap changed by a user" |
| CustomResourceDefinition deleted | **high** | `kubectl delete crd <name>` | finding "CustomResourceDefinition deleted" |
| CustomResourceDefinition created | **medium** | `kubectl apply` a new CRD | finding "CustomResourceDefinition created" |
| APIService registered or changed | **high** | create/modify an aggregated `APIService` | finding "APIService registered or changed" |
| Kubelet API accessed via node proxy | **high** | any request to `…/nodes/<node>/proxy/…` | finding "Kubelet API accessed via node proxy" |
| Node deleted by a user | **high** | `kubectl delete node <n>` under a non-system identity | finding "Node deleted by a user" (autoscalers are system:*, excluded) |

### D. Execution, evasion & destruction (audit shape)

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Exec or attach into a kube-system pod | **high** | `kubectl exec -n kube-system <pod> -- sh` | finding "Exec or attach into a kube-system pod" |
| Kubectl exec into running pod | **medium** | `kubectl exec <pod> -- sh` (any namespace) | finding "Kubectl exec into running pod" |
| Ephemeral (debug) container injected into a pod | **high** | `kubectl debug -it <pod> --image=busybox` | finding "Ephemeral (debug) container injected into a pod" |
| Kubernetes events deleted | **high** | `kubectl delete events --all -n app` | finding "Kubernetes events deleted" |
| Bulk delete (deletecollection) by a user | **high** | any deletecollection under a non-system identity | finding "Bulk delete (deletecollection) by a user" |
| Workload controller deleted by a user | **medium** | `kubectl delete deploy/sts/ds/rs …` under a non-system identity | finding "Workload controller deleted by a user" |
| DaemonSet created | **high** | `kubectl apply` a DaemonSet | finding "DaemonSet created" |
| NetworkPolicy deleted | **high** | `kubectl delete netpol <n>` | finding "NetworkPolicy deleted" |
| NetworkPolicy created or modified | **medium** | create/patch a NetworkPolicy | finding "NetworkPolicy created or modified" |
| Namespace deleted | **high** | `kubectl delete ns <n>` | finding "Namespace deleted" |
| Secret created or modified | **medium** | create/patch a Secret | finding "Secret created or modified" |
| Kubernetes secret read by user identity | **medium** | `kubectl get secret <n>` by a non-serviceaccount identity | finding "Kubernetes secret read by user identity" |
| CronJob created or modified | **medium** | create/patch a CronJob | finding "CronJob created or modified" |

---

## Runtime (Tetragon) rules

**Runtime prerequisites.** `process_exec` rules work on a **bare Tetragon** install.
The file/privilege/kernel/escape/network rules need a **TracingPolicy** to make the
kernel event exist at all — apply the bundle in
[`tetragon-policies/`](../tetragon-policies), which is named `<class>-…` so bragi routes
each event to the right OCSF class. On arm64 nodes swap the `__x64_sys_*` hooks for
`__arm64_sys_*` (bragi normalises the prefix). Without a policy, its rules never fire —
they show as *covered-but-not-detected* in the ATT&CK view, not as an error.

### From `process_exec` (class 1007) — no policy needed

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Binary executed from a writable directory | **critical** | run a binary from `/tmp`, `/dev/shm`, `/run` or `/var/tmp` inside a container | finding "Binary executed from a writable directory" — highest-signal runtime rule |
| Package manager or build tool executed in container | **high** | run `apt`/`apk`/`yum`/`pip`/`npm`/`gcc`/`make` in a running container | finding "Package manager or build tool executed in container" |
| Network client executed in container | **medium** | run `curl`/`wget`/`nc`/`socat`/`ssh`/`nmap`/`telnet` in a container | finding "Network client executed in container" |
| Service-account token piped to a network tool | **critical** | a command line that references the SA token path **and** a transfer tool (`curl`/`wget`/`nc`/`base64`) | finding "Service-account token piped to a network tool" |
| Scheduling-persistence tool run in container | **medium** | run `crontab`/`at`, or `systemctl enable`, in a container | finding "Scheduling-persistence tool run in container" |
| Shell history or log tampering in container | **medium** | `rm -rf /var/log/…`, truncate a log, or clear `.bash_history` | finding "Shell history or log tampering in container" |
| Shell spawned in container (Tetragon) | **high** | `/bin/sh`/`/bin/bash` starts in a container | finding "Shell spawned in container" |
| Container escape tooling executed | **high** | run `nsenter`/`unshare`/`setns` | finding "Container escape tooling executed" |
| Reverse shell pattern in command line | **high** | a command line with `/dev/tcp/…`, `nc -e`, `mkfifo /tmp…` | finding "Reverse shell pattern in command line" |
| Cryptocurrency miner indicators | **critical** | run `xmrig`/`minerd`, or a `stratum+tcp://` / `--donate-level` arg | finding "Cryptocurrency miner indicators" |
| Suspicious system reconnaissance command | **low** | `whoami`/`hostname`/`uname`/`netstat`/`ps` in a container | finding "Suspicious system reconnaissance command" |

### File integrity (class 1001) — needs `1001-file-integrity.yaml`

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Service-account token file read | **critical** | read `/var/run/secrets/kubernetes.io/serviceaccount/token` | finding "Service-account token file read" |
| Write to a persistence-sensitive file | **critical** | write to `ld.so.preload`, `authorized_keys`, a systemd unit, a cron dir, or `rc.local` | finding "Write to a persistence-sensitive file" |
| Write to sensitive system file | **high** | write to `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/cron*` | finding "Write to sensitive system file" |
| AppArmor denied operation | **medium** | any AppArmor `DENIED` (class 1001, activity 6) | finding "AppArmor denied operation" |

### Privilege / escape / kernel

| Rule | Severity | How to trigger | Policy | Expected |
|---|---|---|---|---|
| Runtime capability set acquired | **high** | a `capset()` inside a container | `3001-privileged-syscalls` | finding "Runtime capability set acquired" |
| Privilege change to root | **medium** | `setuid(0)` / `setgid(0)` | `3001-privileged-syscalls` | finding "Privilege change to root" |
| Mount syscall from a container | **high** | `mount`/`umount` from inside a pod | `1007-escape-syscalls` | finding "Mount syscall from a container" |
| Namespace-manipulation syscall from a container | **high** | `setns`/`unshare`/`pivot_root` from a pod | `1007-escape-syscalls` | finding "Namespace-manipulation syscall from a container" |
| Ptrace from a container | **high** | `ptrace` from a pod | `1007-escape-syscalls` | finding "Ptrace from a container" |
| eBPF operation from a container | **high** | `bpf()`/`perf_event_open` from inside a pod | `1003-bpf` | finding "eBPF operation from a container" (host-level bpf stays low via "eBPF program or map activity") |
| eBPF program or map activity | **low** | any bpf event (host or container) | `1003-bpf` | finding "eBPF program or map activity" |
| Kernel module loaded from a container | **critical** | `init_module`/`finit_module` from a pod | `1005-kernel-modules` | finding "Kernel module loaded from a container" |
| Kernel module loaded | **high** | any module load (host) | `1005-kernel-modules` | finding "Kernel module loaded" |
| Writable-executable memory protection change | **medium** | `mprotect` to RWX | `1004-memory` | finding "Writable-executable memory protection change" |

### Runtime network (class 4001) — needs `4001-egress-connect.yaml`

| Rule | Severity | How to trigger | Expected |
|---|---|---|---|
| Pod connected to the cloud metadata service | **critical** | a pod connecting to `169.254.169.254` (IMDS) | finding "Pod connected to the cloud metadata service" |
| Container connecting to non-RFC1918 destination | **low** | a pod egressing to a public IP | finding "Container connecting to non-RFC1918 destination" |

---

## Whitelisting model (the point of the design)

In a hardened cluster the sensitive-primitive rules (privileged, hostPath, host
namespaces, dangerous caps, DaemonSet, webhooks, module load, …) will fire on your
**own** infrastructure on day one — CNI/CSI hostPaths, cert-manager webhook patches,
CD service accounts. That is the design working: each legitimate hit is whitelisted
by its identifying field (rule + workload for runtime/watch rules, rule + actor for
audit rules), and from then on **anything unidentified doing the same thing alerts at
face value**. Whitelist from the Events page; do not disable the rule.
