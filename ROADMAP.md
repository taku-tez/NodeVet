# NodeVet Roadmap

Kubernetesノード・kubelet・ランタイム層のセキュリティ検証ツール。
ワークロード層 (ManifestVet) が見ているPod設定に対し、NodeVet はその下の
kubelet設定・OS・コンテナランタイム・ノードアクセス制御を検証する。

---

## v0.1.0 — kubelet 設定検証 (Week 1–2)

**Goal:** kubelet の起動フラグ・設定ファイルのセキュリティ設定を静的に評価する。

### 認証・認可
- [x] `--anonymous-auth=false` の確認 (デフォルト true は危険) — NV1001
- [x] `--authorization-mode=Webhook` の確認 (`AlwaysAllow` は禁止) — NV1002
- [x] `--client-ca-file` の設定確認 — NV1003
- [x] `--read-only-port=0` の確認 (デフォルト 10255 は認証なし) — NV1004

### TLS設定
- [x] `--tls-cert-file` / `--tls-private-key-file` の設定確認 — NV1101, NV1102
- [x] `--tls-cipher-suites` の安全な暗号スイートの使用確認 — NV1103
- [x] `--rotate-certificates=true` の確認 — NV1104
- [x] `--rotate-server-certificates=true` の確認 — NV1105

### Pod・コンテナ制御
- [x] `--protect-kernel-defaults=true` の確認 — NV1201
- [x] `--make-iptables-util-chains=true` の確認 — NV1202
- [x] `--event-qps=0` でないこと (DoS 対策) — NV1203
- [x] `--streaming-connection-idle-timeout` の設定確認 — NV1204

### 設定ソース対応
- [x] `KubeletConfiguration` YAML ファイルのスキャン
- [x] kubelet 起動フラグの直接解析
- [x] `kubectl get --raw /api/v1/nodes/<name>/proxy/configz` からのランタイム設定取得

---

## v0.2.0 — ライブノード検証 (Week 3–4)

**Goal:** 稼働中クラスターのノード設定をリモートから評価する。

### ノード情報収集
- [x] `kubectl get nodes -o json` からのノード設定収集
- [x] Node のアノテーション・ラベルからのセキュリティ設定読み取り
- [x] `kubectl get --raw /api/v1/nodes/<name>/proxy/configz` での kubelet 設定取得 (v0.1.0で実装)
- [x] Node Conditions (`Ready`, `MemoryPressure`, `DiskPressure`) の確認 — NV3001-NV3003

### GKE/EKS/AKS 固有チェック
- [x] **GKE**:
  - Shielded Nodes (vTPM / Integrity Monitoring) の有効化確認 — NV4001, NV4003
  - Secure Boot の有効化確認 — NV4002
  - Node Auto-Upgrade の設定確認 — NV4005
  - Workload Identity の有効化確認 — NV4004
  - Binary Authorization の有効化確認 — NV4006
- [x] **EKS**:
  - AMI の最新化確認 (managed node group の update policy) — NV4103
  - IMDSv2 の強制確認 (`hop-limit=1`) — NV4101
  - EBS ボリュームの暗号化確認 — NV4102
- [x] **AKS**:
  - Azure Defender for Containers の有効化確認 — NV4201
  - OS Disk の暗号化確認 — NV4202

### スキャンオプション
- [x] `nodevet cluster --context <name>`
- [x] `--node <node-name>` で特定ノードのみ
- [x] `--all-nodes` で全ノード

---

## v0.3.0 — コンテナランタイム検証 (Week 5–6)

**Goal:** containerd / CRI-O のセキュリティ設定を評価する。

### containerd
- [x] `config.toml` の設定検証
  - `enable_unprivileged_ports` / `enable_unprivileged_icmp` の設定 — NV2001, NV2002
  - `snapshotter` の設定確認 — NV2003
  - レジストリミラー設定の安全性 — NV2004
- [x] `restrict_oci_annotations` の設定確認 — NV2005
- [x] rootless containerd の設定確認 — NV2007

### seccomp / AppArmor
- [x] デフォルト seccomp プロファイルの適用確認 — NV2006
- [ ] AppArmor プロファイルのノードへのロード確認 (v0.4.0で対応予定)
- [ ] `RuntimeDefault` 以外のカスタムプロファイルの妥当性チェック (v0.4.0で対応予定)
- [ ] `Unconfined` プロファイル使用の検出 (v0.4.0で対応予定)

### RuntimeClass
- [x] `RuntimeClass` (gVisor/Kata Containers) の設定確認 — NV2101
- [x] 高リスクワークロードへの sandboxed runtime 適用推奨 — NV2101
- [x] `runtimeHandler` の有効性確認 — NV2102

---

## v0.4.0 — ノードアクセス制御 (Week 7)

**Goal:** ノードへの過剰アクセスパスを検出する。

### Node Authorization
- [x] Node Authorizer の有効化確認 — NV3101
- [x] NodeRestriction Admission Plugin の確認 — NV3102
- [x] kubelet の API Server へのアクセス範囲の確認 (NV3101-NV3102で対応)

### SSH / OS アクセス
- [x] ノードへの直接 SSH アクセスの有無検出 (GKE: `gcloud compute ssh` 設定) — NV3202
- [x] IAP (Identity-Aware Proxy) / Bastion ホスト経由かの確認 — NV3202
- [ ] ノードのファイアウォールルール検証 (GCP: `gcloud compute firewall-rules`) (v0.5.0+)
- [x] OS Login の有効化確認 (GKE) — NV3201

### `kubectl debug` / `kubectl exec` リスク
- [x] ノードへの `kubectl debug` を許可する RBAC 設定の検出 — NV3301
- [x] `hostPID: true` Pod を経由したノードエスケープパスの検出 — NV3303
- [x] privileged Pod からのノードファイルシステムアクセスパスの可視化 — NV3304

---

## v0.5.0 — 監査ログ検証 (Week 8–9)

**Goal:** Kubernetes 監査ログの設定の完全性を評価する。

### 監査ポリシー評価
- [x] `--audit-log-path` の設定確認 — NV5001
- [x] `--audit-log-maxage` / `--audit-log-maxbackup` / `--audit-log-maxsize` の確認 — NV5002-NV5004
- [x] `AuditPolicy` の completeness チェック — NV5101-NV5106
  - `Secrets` リソースへのアクセスが記録されているか — NV5101
  - `exec` / `attach` アクションが記録されているか — NV5102
  - `system:anonymous` のアクションが記録されているか — NV5103
  - `ResponseComplete` レベルでの記録確認 — NV5104
- [x] 監査ログの外部転送設定 (Cloud Logging / Fluentd) の確認 — NV5006

### ログの完全性ギャップ検出
- [x] 記録されていない重要操作の洗い出し — NV5101-NV5106で対応
- [x] 推奨 AuditPolicy の自動生成 (`--emit-policy`) — `nodevet audit --emit-policy`

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

---

## 精度改善 (v0.5.x — v0.6.0 の間)

**Goal:** 偽陽性・偽陰性を削減し、複合攻撃パスを可視化する。

### 偽陽性削減 (FP削減)
- [x] システム namespace 除外: `kube-system` / `kube-public` / `kube-node-lease` の Pod は NV3303-NV3305 で除外
- [x] RBAC システムロールスキップ: `system:*` / `cluster-admin` は NV3301-NV3302 で除外
- [x] AuditPolicy broad suppressor 検出 (NV5107): 前段の `level:None` ルールが他ルールをシャドウする問題を検出

### 偽陰性削減 (FN削減)
- [x] NV3305: hostPID + privileged の組み合わせをノードエスケープチェーンとして CRITICAL 判定
- [x] NV5107: 広範な `None` ルールで AuditPolicy が実質無効化されるケースを検出
- [x] NV7001: Kubernetes バージョン陳腐化 (EOL: CRITICAL / 2+ 遅れ: HIGH)
- [x] NV7002: containerd 既知 CVE バージョン (1.6.x < 1.6.27 / 1.7.x < 1.7.14)
- [x] NV7003: Linux カーネル コンテナエスケープ CVE (< 4.19: CRITICAL / < 5.4: HIGH / < 5.15: MEDIUM)

### 深刻度精度向上
- [x] `SeverityOverride` による finding 単位の深刻度オーバーライド (AccessFinding / NodeFinding)
- [x] RBAC dangerous subject 判定: `system:authenticated` / `system:unauthenticated` / `system:serviceaccounts` を CRITICAL に昇格
- [x] TLS cipher suite: `knownInsecureSuites` マップで既知脆弱 vs 未認識を区別

### Remediation 出力
- [x] 全テーブルレンダラーに REMEDIATION カラム追加
- [x] AuditPolicy finding に `(matched by rule #N)` でシャドウ元ルールを表示

### Config Drift 検出
- [x] `--config`/`--flags` + `--node` 併用時に静的設定 vs ライブ設定の乖離を検出・報告

### 複合攻撃パス相関 (nodevet scan)
- [x] `nodevet scan` コマンド: 全チェックを実行し fired rule ID を集約
- [x] C001-C005: 複合条件から攻撃パスを推論 (例: exec許可 + 監査なし = 証跡ゼロのリモート実行)

---

## v0.6.0 — eBPF / ランタイムセキュリティ設定検証 (Week 10)

**Goal:** Falco・Tetragon・Cilium の設定を静的に評価する。

### Falco
- [x] Falco DaemonSet の設定確認 — NV6001
- [x] Falco ルールファイルのセキュリティ評価
  - 重要ルールが `override: enabled: false` で無効化されていないか — NV6002
- [x] Falco のアウトプット設定 (SIEM 連携) の確認 — NV6003

### Tetragon (Cilium)
- [x] TracingPolicy の適用範囲確認 — NV6101
- [x] 特権操作のトレース設定確認 — NV6102

### Cilium
- [x] Hubble の有効化確認 (可視性) — NV6201
- [x] `--enable-l7-proxy` の設定確認 — NV6202

---

## ルールID体系

```
NV1xxx  kubelet 設定 (認証・TLS・Pod制御)
NV2xxx  コンテナランタイム (containerd/CRI-O)
NV3xxx  OS・ノードアクセス制御 (RBAC・SSH・Pod リスク)
NV4xxx  マネージドクラスター固有 (GKE/EKS/AKS)
NV5xxx  監査ログ設定 (フラグ + AuditPolicy completeness)
NV6xxx  eBPF・ランタイムセキュリティ (Falco/Tetragon/Cilium)
NV7xxx  バージョン陳腐化 (Kubernetes / containerd / Linux kernel)
Cxxx    複合攻撃パス相関 (nodevet scan が生成)
```
