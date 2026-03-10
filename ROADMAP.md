# NodeVet Roadmap

Kubernetesノード・kubelet・ランタイム層のセキュリティ検証ツール。
ワークロード層 (ManifestVet) が見ているPod設定に対し、NodeVet はその下の
kubelet設定・OS・コンテナランタイム・ノードアクセス制御を検証する。

---

## v0.1.0 — kubelet 設定検証 (Week 1–2)

**Goal:** kubelet の起動フラグ・設定ファイルのセキュリティ設定を静的に評価する。

### 認証・認可
- [ ] `--anonymous-auth=false` の確認 (デフォルト true は危険)
- [ ] `--authorization-mode=Webhook` の確認 (`AlwaysAllow` は禁止)
- [ ] `--client-ca-file` の設定確認
- [ ] `--read-only-port=0` の確認 (デフォルト 10255 は認証なし)

### TLS設定
- [ ] `--tls-cert-file` / `--tls-private-key-file` の設定確認
- [ ] `--tls-cipher-suites` の安全な暗号スイートの使用確認
- [ ] `--rotate-certificates=true` の確認
- [ ] `--rotate-server-certificates=true` の確認

### Pod・コンテナ制御
- [ ] `--protect-kernel-defaults=true` の確認
- [ ] `--make-iptables-util-chains=true` の確認
- [ ] `--event-qps=0` でないこと (DoS 対策)
- [ ] `--streaming-connection-idle-timeout` の設定確認

### 設定ソース対応
- [ ] `KubeletConfiguration` YAML ファイルのスキャン
- [ ] kubelet 起動フラグの直接解析
- [ ] `kubectl get --raw /api/v1/nodes/<name>/proxy/configz` からのランタイム設定取得

---

## v0.2.0 — ライブノード検証 (Week 3–4)

**Goal:** 稼働中クラスターのノード設定をリモートから評価する。

### ノード情報収集
- [ ] `kubectl get nodes -o json` からのノード設定収集
- [ ] Node のアノテーション・ラベルからのセキュリティ設定読み取り
- [ ] `kubectl get --raw /api/v1/nodes/<name>/proxy/configz` での kubelet 設定取得
- [ ] Node Conditions (`Ready`, `MemoryPressure`, `DiskPressure`) の確認

### GKE/EKS/AKS 固有チェック
- [ ] **GKE**:
  - Shielded Nodes (vTPM / Integrity Monitoring) の有効化確認
  - Secure Boot の有効化確認
  - Node Auto-Upgrade の設定確認
  - Workload Identity の有効化確認
  - Binary Authorization の有効化確認
- [ ] **EKS**:
  - AMI の最新化確認 (managed node group の update policy)
  - IMDSv2 の強制確認 (`hop-limit=1`)
  - EBS ボリュームの暗号化確認
- [ ] **AKS**:
  - Azure Defender for Containers の有効化確認
  - OS Disk の暗号化確認

### スキャンオプション
- [ ] `nodevet --cluster --context <name>`
- [ ] `--node <node-name>` で特定ノードのみ
- [ ] `--all-nodes` で全ノード

---

## v0.3.0 — コンテナランタイム検証 (Week 5–6)

**Goal:** containerd / CRI-O のセキュリティ設定を評価する。

### containerd
- [ ] `config.toml` の設定検証
  - `enable_unprivileged_ports` / `enable_unprivileged_icmp` の設定
  - `snapshotter` の設定確認
  - レジストリミラー設定の安全性
- [ ] `restrict_oci_labels_annotation` の設定確認
- [ ] rootless containerd の設定確認

### seccomp / AppArmor
- [ ] デフォルト seccomp プロファイルの適用確認
- [ ] AppArmor プロファイルのノードへのロード確認
- [ ] `RuntimeDefault` 以外のカスタムプロファイルの妥当性チェック
- [ ] `Unconfined` プロファイル使用の検出

### RuntimeClass
- [ ] `RuntimeClass` (gVisor/Kata Containers) の設定確認
- [ ] 高リスクワークロードへの sandboxed runtime 適用推奨
- [ ] `runtimeHandler` の有効性確認

---

## v0.4.0 — ノードアクセス制御 (Week 7)

**Goal:** ノードへの過剰アクセスパスを検出する。

### Node Authorization
- [ ] Node Authorizer の有効化確認
- [ ] NodeRestriction Admission Plugin の確認
- [ ] kubelet の API Server へのアクセス範囲の確認

### SSH / OS アクセス
- [ ] ノードへの直接 SSH アクセスの有無検出 (GKE: `gcloud compute ssh` 設定)
- [ ] IAP (Identity-Aware Proxy) / Bastion ホスト経由かの確認
- [ ] ノードのファイアウォールルール検証 (GCP: `gcloud compute firewall-rules`)
- [ ] OS Login の有効化確認 (GKE)

### `kubectl debug` / `kubectl exec` リスク
- [ ] ノードへの `kubectl debug` を許可する RBAC 設定の検出
- [ ] `hostPID: true` Pod を経由したノードエスケープパスの検出
- [ ] privileged Pod からのノードファイルシステムアクセスパスの可視化

---

## v0.5.0 — 監査ログ検証 (Week 8–9)

**Goal:** Kubernetes 監査ログの設定の完全性を評価する。

### 監査ポリシー評価
- [ ] `--audit-log-path` の設定確認
- [ ] `--audit-log-maxage` / `--audit-log-maxbackup` / `--audit-log-maxsize` の確認
- [ ] `AuditPolicy` の completeness チェック
  - `Secrets` リソースへのアクセスが記録されているか
  - `exec` / `attach` アクションが記録されているか
  - `system:anonymous` のアクションが記録されているか
  - `ResponseComplete` レベルでの記録確認
- [ ] 監査ログの外部転送設定 (Cloud Logging / Fluentd) の確認

### ログの完全性ギャップ検出
- [ ] 記録されていない重要操作の洗い出し
- [ ] 推奨 AuditPolicy の自動生成 (`--emit-policy`)

---

## v0.6.0 — eBPF / ランタイムセキュリティ設定検証 (Week 10)

**Goal:** Falco・Tetragon・Cilium の設定を静的に評価する。

### Falco
- [ ] Falco DaemonSet の設定確認
- [ ] Falco ルールファイルのセキュリティ評価
  - デフォルトルールが有効か
  - 重要ルールが `override: enabled: false` で無効化されていないか
  - カスタムルールのロジック検証
- [ ] Falco のアウトプット設定 (SIEM 連携) の確認

### Tetragon (Cilium)
- [ ] TracingPolicy の適用範囲確認
- [ ] 特権操作のトレース設定確認

### Cilium
- [ ] Cilium NetworkPolicy の設定評価 (NetworkVet と協調)
- [ ] Hubble の有効化確認 (可視性)
- [ ] `--enable-l7-proxy` の設定確認

---

## K8sVet 取り込み計画

| バージョン | K8sVet対応 | 内容 |
|---|---|---|
| NodeVet v0.1.0 完了後 | K8sVet v0.5.0 | `k8svet scan --cluster` に kubelet 設定スキャン追加 |
| NodeVet v0.2.0 完了後 | K8sVet v0.5.0 | GKE/EKS/AKS 固有チェックを `--cluster` に統合 |
| NodeVet v0.5.0 完了後 | K8sVet v0.6.0 | `k8svet scan --cluster` に監査ログ検証を追加 |

```bash
# K8sVet統合後のイメージ
k8svet scan --cluster --all-namespaces
# → [ManifestVet]   cluster://    361 errors, 1549 warnings
# → [RBACVet]       cluster://    212 errors, 1853 warnings
# → [NetworkVet]    cluster://      0 errors,   10 warnings
# → [NodeVet]       cluster://      8 errors,   14 warnings   ← 新規
#      kubelet anonymous-auth=true (node-pool-3 x3)
#      read-only-port=10255 open (node-pool-3 x3)
#      Shielded Nodes disabled
#      Binary Authorization disabled

k8svet scan --cluster --node gke-cdp-dev-tokyo-k8s-v2-node-pool-3-ed9d02d6-q64q
# → [NodeVet]  node://gke-.../q64q  3 errors, 5 warnings
```

### 検出→アクションの連携
NodeVet の結果は AdmissionVet・ComplianceVet と組み合わせることで価値が高まる。

```
NodeVet: kubelet anonymous-auth=true を検出
  ↓
ComplianceVet: CIS 4.2.1 FAIL にマッピング
  ↓
AdmissionVet: NodeRestriction Admission Plugin の有効化ポリシー生成
```

---

## ルールID体系

```
NV1xxx  kubelet 設定
NV2xxx  コンテナランタイム (containerd/CRI-O)
NV3xxx  OS・ノードアクセス制御
NV4xxx  マネージドクラスター固有 (GKE/EKS/AKS)
NV5xxx  監査ログ設定
NV6xxx  eBPF・ランタイムセキュリティ (Falco/Tetragon)
```
