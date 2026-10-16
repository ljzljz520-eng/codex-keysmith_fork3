# Release 签名信任体系（离线根密钥 + Rekor 透明日志）- 产品需求文档

## Overview

- **Summary**: 为 codex-keysmith 的稳定版 CLI 资产与桌面 beta 资产建立一套 TUF 风格的离线签名信任体系：air-gap Ed25519 根密钥 → release 签名密钥 → 签名 release manifest（绑定源码 commit、构建器、CLI/桌面/bundle 全部资产 digest 与 SPDX/CycloneDX 双 SBOM），manifest 同步锚定到 Sigstore Rekor 透明日志；提供零依赖、可离线运行的验证器与本地信任状态（最高可信版本水位、密钥轮换、版本/资产/密钥撤销、显式降级 override 与审计），并改造 GitHub 发布流程使"无签名不发布"。
- **Purpose**: 当前用户从同一 GitHub Release 下载脚本与 `SHA256SUMS`，只能发现传输损坏；发布账号或 Runner 被入侵、资产被替换、诱导用户回滚到易受攻击版本均无法阻止。新体系使攻击者即使完全控制 GitHub 账号与 CI Runner，也无法伪造可通过验证的 release；删除/替换行为可被透明日志与本地水位检测。
- **Target Users**:
  - 通过单文件脚本或 zip/tar 安装 CLI 的最终用户（含离线环境、macOS/Linux/Windows）；
  - 下载未签名桌面 beta（DMG/NSIS）的用户；
  - 代装的编码智能体（agent-install 流程）；
  - 执行密钥仪式、轮换、紧急撤销的维护者；
  - 审计发布链路的安全研究人员。

## Goals

- release manifest 由离线 Ed25519 release 密钥签名，release 密钥由离线 root 密钥认证；默认验证路径全程离线、纯 Python 标准库、Python 3.9–3.14 跨平台。
- manifest 绑定：源码 commit 与注释 tag object、构建器身份（workflow SHA、runner、工具链版本、桌面 build-manifest digest）、全部分发资产（CLI 单文件/zip/tar/scenario bundle/SHA256SUMS/桌面 DMG/NSIS/candidate zip）的 SHA-256 与大小、SPDX 2.3 与 CycloneDX 1.6 双 SBOM digest。
- 每个签名 manifest 以 hashedrekord 形式存在于 Sigstore Rekor 透明日志，可在线验证 SET 签名、Merkle inclusion proof 与日志树水位；CI 把 Rekor 条目作为发布门禁。
- 本地持久化每条发布线（stable / desktop-beta）的最高可信版本与单调序号，防回滚；显式 downgrade override 必须带原因并写入只追加审计；被撤销版本不能被普通降级旁路绕过。
- 支持 root/release 密钥轮换（旧签名持续可验、新签名被接受、root 不可回滚）、版本/资产/密钥三类撤销，以及紧急撤销的四条传播渠道（随 release 附带、仓库受保护路径、在线刷新、离线 side-load）。
- 兼容：离线安装、跨平台签名与验证、未签名旧版本用户的一次性迁移（legacy onboarding）、历史 release 不可变。

## Non-Goals

- 不申请/集成 Apple Developer ID、Authenticode 或 SignPath 原生二进制签名（与现有 SignPath Foundation 申请互不替代；桌面安装包仍标注 unsigned，但获得 manifest 级分发信任）。
- 不在产品运行时（codex-instruct.py 默认路径）引入任何网络访问；不做自动更新/自动下载。
- 不防止用户主动运行自己已持有、未经验证的旧脚本（信任门禁作用于分发/安装渠道与已记录的接受状态，不做操作系统级执行控制）。
- 不在本次生成或持有任何真实主密钥；真实 root/release 密钥由维护者按 runbook 在 air-gap 机器生成，仓库内只出现测试 fixture 密钥。
- 不改变 v0.6.0 及更早历史 release 的资产集合与发布状态；不 bump VERSION 发布新版本（工具与工作流先落地 main，首个签名版本由维护者密钥仪式后声明）。
- 不构建 TUF 全量角色（timestamp/snapshot/mirrors）；采用最小角色集（root、release、revocation 归 root）与本地水位替代。
- 不解决首次用户从同一被攻陷渠道同时获取验证器与 root 公钥的 TOFU 固有局限（仅通过多渠道指纹发布缓解，并在文档中如实说明威胁模型）。

## Background & Context

- 稳定版发布链路：[release.yml](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/.github/workflows/release.yml) 在注释 tag（GitHub API 核验 GPG `verified=true`）上由 [build_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/build_release.py) 双构建可复现地产出 5 个资产（zip、tar.gz、单文件 CLI、scenarios.bundle、`SHA256SUMS`），发布时校验 GitHub 侧资产 digest 集合且禁止覆盖。
- 桌面 beta：[desktop-candidate.yml](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/.github/workflows/desktop-candidate.yml) 在 macOS/Windows pinned runner 构建，[validate_desktop_candidate.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/validate_desktop_candidate.py) 产出每平台 `build-manifest.json`（source commit、target triple、Node/Python/PyInstaller/Rust 版本、资产 digest），[package_desktop_prerelease.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/package_desktop_prerelease.py) 汇总 DMG/NSIS/candidate zip 与 `SHA256SUMS`。
- CLI 是约 1.77 万行零依赖单文件，Python 3.10+ 建议（CI 兼容性测试覆盖 3.9），状态目录 `~/.codex-keysmith`；README 与 [agent-install.md](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/docs/agent-install.md) 的安装指引为"下载资产 + 同渠道 SHA256SUMS 校验"，并明确禁止 `curl | python`。
- [CODE_SIGNING_POLICY.md](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/CODE_SIGNING_POLICY.md) 已确立：不可覆盖发布、main-only 手动发布、签名注释 tag、资产集合一致等强控制；本体系在其上叠加密码学层。
- CI 矩阵：ubuntu-24.04 / macos-15（Python 3.9、3.14）、windows-2025（3.10/3.12/3.14）；Ruff target py38；新代码必须 3.9 语法兼容（`from __future__ import annotations`，避免运行时 PEP 604）。

## Functional Requirements

### 信任元数据

- **FR-1 信封格式**：所有签名文档统一为 `{"signed": {...}, "signatures": [{"keyid": ..., "sig": <hex>}]}`；签名负载为规范字节序列（UTF-8、`json.dumps(ensure_ascii=False, indent=2, sort_keys=True)` + `"\n"`，与仓库现有确定性 JSON 约定一致）；签名为 Ed25519 对该字节序列的签名；`keyid` 为 32 字节公钥的带类型前缀 SHA-256 hex。
- **FR-2 root 元数据**：`_type=root`，含 `version`（单调整数）、角色表（root / release / revocation 的 keyids 与 threshold）、密钥字典（keytype=ed25519、公钥 hex）、受信 Rekor 日志公钥列表（keyid + PEM）、`expires`、`spec_version`。root v(N+1) 必须由 v(N) 的 root 角色密钥按 threshold 签名（允许同时附 v(N+1) 新密钥签名以便前向验证）。
- **FR-3 release manifest**：每条发布线一个清单，含 `_type=release`、`product`、`release_line`（stable | desktop-beta）、`version`、`tag`、单调 `sequence`（每发布线独立计数，从 1 开始）、`issued_at`（UTC ISO-8601）、`source`（repo、40/64 位 commit、annotated tag object SHA）、`builder`（workflow 名/ref/SHA、runner 镜像、Python/Node/Rust/PyInstaller 版本、桌面线每平台 `build-manifest.json` 的 sha256）、`artifacts`（资产名 → sha256+size）、`sboms`（SBOM 文件名 → sha256+size）、`required_root_version`、`required_revocations_version`。
- **FR-4 资产覆盖范围**：
  - stable 线：`codex-keysmith-v<X>.zip`、`.tar.gz`、`codex-instruct-v<X>.py`、`codex-keysmith-scenarios-v<X>.bundle`、`SHA256SUMS`、验证器单文件 `verify-release-v<X>.py`、两份 SBOM、签名 envelope 自身对应的 `release-manifest.json` 摘要由 release-index 锚定。
  - desktop-beta 线：macOS DMG、两个平台 candidate zip、Windows NSIS setup、桌面 `SHA256SUMS`、每平台 `build-manifest.json`、两份桌面 SBOM、验证器单文件。
- **FR-5 release index**：`_type=release-index`，release 密钥签名，按发布线列出全部已发布版本（version、sequence、manifest 规范字节 sha256、rekor log index/uuid），自身 version 单调；作为通道级防回滚锚点，随每个 release 重新发布累积副本。
- **FR-6 revocations**：`_type=revocations`，由 root 角色密钥签名（紧急通道不依赖可能被撤的 release 密钥），含单调 `version`、`issued_at`、较短 `expires`（建议 30 天）、`revoked_keys`（keyid+原因+时间）、`revoked_releases`（发布线+版本或版本范围+严重度+原因+替代版本+是否允许安全例外）、`revoked_artifacts`（sha256+原因）。文档只增不删：新版本必须包含全部未过期的历史撤销项。
- **FR-7 本地信任状态**：目录 `~/.codex-keysmith/trust/`（Windows 同名目录），包含已固定 root、最高 revocations 副本、最高 release-index 副本、每线 `accepted`（version/sequence/manifest hash/UTC 时间）、只追加 `audit.jsonl`；写入必须临时文件 + 原子 rename（best-effort fsync），目录 0700、文件 0600；支持 `--trust-dir` 重定位（企业/离线批量场景）。

### 验证器（verify-release 单文件，纯标准库）

- **FR-8 验证顺序（fail-closed）**：定位/引导 root → root 版本不可回滚 → 元数据 schema/签名/threshold → release keyid 未被撤销且在当前 root 角色表 → index 与 manifest 摘要一致 → 各资产 sha256/size 全部命中 → SBOM 摘要命中 → revocations（密钥/版本/资产）→ 水位/降级判定 →（可选在线）Rekor → 全部通过后原子更新本地状态并写审计。任一环节失败立即非零退出且不更新水位。
- **FR-9 root 引导**：优先 `--root-file`，其次信任目录缓存，再次仓库/发布渠道提供的 `root.1.json`（TOFU）；TOFU 时必须显著打印 root 指纹（SHA-256 分组格式）并要求用户与多渠道公布值比对；固定后的 root 不再接受同渠道静默替换。
- **FR-10 资产验证**：对下载目录逐文件流式 sha256 + 字节数核对；额外校验 `SHA256SUMS` 内部摘要与 manifest 一致（保持与旧工具链互操作）；任何多余/缺失/不匹配资产均拒绝。
- **FR-11 来源/构建器核验**：离线模式核验 manifest 内部一致性（tag↔version、commit 形状、桌面 `build-manifest.json` 摘要与其内容、版本与 VERSION 声明）；在线模式（`--refresh-online`）额外用 git/HTTPS 核对远端注释 tag 的 peeled commit 与 tag object，拒绝不一致。
- **FR-12 水位与降级**：通过验证的版本，其 sequence/version 必须高于本地已接受水位；低于水位默认拒绝。`--allow-downgrade <version> [--reason <text>]` 显式旁路（版本必须精确匹配、reason 非空），旁路写入审计（UTC 时间、from/to、manifest hash、reason）。命中 `revoked_releases`/`revoked_artifacts` 时普通降级旁路无效；须 `--accept-revoked <version> --reason <text>` 精确指定版本且 manifest 提供的 `security_exception_allowed=true` 才放行，审计并在信任状态中持续显示活动安全例外警告。
- **FR-13 撤销判定与传播**：验证器读取信任目录中最高版本 revocations；同时支持 `--refresh-online`（从仓库受保护原始 URL 拉取并验证）与 `--revocations-file` 离线 side-load；接受的新撤销文档 version 必须更高且内容包含历史未过期项（防静默丢撤销）。文档过期只产生明确警告与刷新指引，不使已列撤销失效、也不自动放行。
- **FR-14 透明日志验证（可选在线）**：`--rekor` 模式校验 `rekor-entry.json`：body 中 hash 等于 manifest 规范字节 sha256、publicKey 与签名者公钥一致、签名与 envelope 一致；SET 用 root 元数据中受信 Rekor 公钥（ECDSA P-256，纯标准库实现验签）核验；inclusion proof 按 RFC 6962 验证 leaf hash 与路径；观测到的 tree size 单调写入本地，较小树拒绝。无网络/未指定时该环节不执行且不影响离线结论，但输出提示"未做透明日志核验"。
- **FR-15 跨平台与兼容性**：验证器与引擎支持 Python 3.9–3.14、Windows/macOS/Linux；仅用标准库；路径处理遵循仓库既有跨平台安全规则（禁符号链接祖先、保留名、大小写冲突等，参照 build_release.py）；非交互环境（CI/agent）可机器解析输出（`--json`），退出码稳定。
- **FR-16 独立分发形态**：引擎为 `scripts/keysmith_trust.py`；`scripts/verify_release.py` 为薄 CLI；发布时由 build_release.py 以与 standalone CLI 相同的嵌入方式合成单文件 `verify-release-v<X>.py`（shebang + license + 引擎 + CLI），可独立分发、独立审计。

### 维护者离线签名工具

- **FR-17** `scripts/keysmith_signing.py`（纯标准库，三平台可运行，仅维护者使用）子命令：
  - `keygen --role root|release --out <dir>`：生成 Ed25519 密钥对、打印指纹与 air-gap 保管指引；
  - `root-init` / `root-rotate`：生成 root v1 / v(N+1)（旧 root threshold 签名、角色/密钥/Rekor 公钥变更）；
  - `release-key add|retire`：在新 root 中登记/退役 release 公钥；
  - `sign-manifest --input <unsigned.json> --release-key <file>`：输出签名 envelope（支持 threshold 多签追加）；
  - `sign-index`：累积更新并签名 release-index；
  - `revoke --kind key|release|artifact ...`：用 root 密钥签发新版 revocations；
  - `rekor-submit --manifest <signed.json> --rekor-url <url>`：提交 hashedrekord（stdlib urllib，仅该子命令联网；URL 可指向公共实例或 staging），回填 `rekor-entry.json` 并轮询 inclusion；
  - 所有子命令默认拒绝把私钥写入仓库路径，拒绝在含 `.git` 的目录输出私钥（除非显式 `--i-know-this-is-not-a-repo`）。
- **FR-18 纯标准库 Ed25519**：引擎内置 RFC 8032 Ed25519 sign/verify/keygen（不依赖 cryptography/PyNaCl），配套 RFC 8032 官方测试向量；公钥采用简单 hex 容器格式并提供与 `ssh-keygen`/`openssl` 指纹交叉核对的说明；ECDSA P-256 仅实现 verify 路径。

### SBOM

- **FR-19** `scripts/generate_sbom.py` 纯标准库、确定性双格式输出：
  - SPDX 2.3 JSON：文档命名、Package 关系、文件 sha256、license（MIT）、构建器与工具链信息；CLI 线覆盖仓库固定发布文件集与 scenarios/fixture_packs；桌面线额外从 `gui/package-lock.json`、`gui/src-tauri/Cargo.lock`、`gui/requirements-build.txt` 提取 npm/crate/PyInstaller 组件及版本/许可。
  - CycloneDX 1.6 JSON：等价组件/依赖/哈希集合。
  - 两次运行字节一致；输出文件进入 manifest `sboms` 并被签名绑定；字段缺失或解析失败时 fail-closed。

### CLI 集成

- **FR-20** codex-instruct.py 增加（仅本地、无网络）：
  - `--trust-status`：展示 root 指纹/版本、各发布线最高接受版本与 sequence、revocations 版本与到期状态、活动安全例外、最近审计条目；
  - standalone 发布形态在文件名符合 `codex-instruct-v<X>.py` 且信任目录存在对应 accepted 记录时，对自身文件做 sha256 自洽性核对：不一致则在部署类命令（`--yes` 等）上 fail-closed 并提示先用验证器核验；源码树形态（`codex-instruct.py`）与无信任状态时仅信息性提示；
  - 检测到未签名旧版本遗留状态时提供一次性 legacy onboarding：记录审计事件 `legacy-onboarding`（含旧版本声明、UTC 时间、显式确认方式），不阻断既有功能；
  - 不新增任何默认网络调用；既有命令行为与测试不回归。

### 发布流程

- **FR-21 stable 发布改造**：tag push 触发的 [release.yml](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/.github/workflows/release.yml) 保持构建/双构建/注释 tag 核验不变，但：当 tag ≥ 仓库 `trust/policy.json` 声明的 `first_signed_version` 时，Release 仅以 **draft** 创建并上传资产 + 未签名 manifest + 双 SBOM + 验证器单文件；新增 main-only `workflow_dispatch` 工作流（或等价受控 job）接收维护者离线产出的签名 manifest、release-index、rekor-entry，重新独立核对全部摘要、root/release 签名、Rekor inclusion 与远端 tag 后才允许 `draft=false`；缺少任一签名物料一律不得公开。tag 低于 first_signed_version 时走旧流程（仅历史重放场景）。
- **FR-22 桌面 beta 改造**：桌面 beta 发布门同样要求签名 desktop-beta manifest（覆盖 FR-4 桌面资产）、双 SBOM 与 rekor-entry；既有 candidate 构建与 signed annotated desktop tag 控制不变；签名物料校验通过前 beta Release 保持 draft。
- **FR-23 CI 门禁**：新增测试/校验使 PR 必须通过：引擎/验证器/SBOM 单测（含无网络证明）、签名链路端到端 fixture 演练、Rekor 交互的录制重放测试；发布工作流中 Rekor 条目用 `sigstore-python`（仅 CI 临时安装）作为 oracle 与纯标准库验证器交叉核对，二者结论必须一致。
- **FR-24 仓库信任物料布局**：`trust/policy.json`（product、发布线、`first_signed_version`、rekor URL、渠道 URL 模板；首版该字段为 null，runbook 指导仪式后启用）、`trust/root/`、`trust/revocations/`（真实物料在维护者仪式后提交；目录提供 README 式说明并入 SECURITY/CODE_SIGNING_POLICY 文档，不新增多余 md）；测试 fixture 物料只存在于 `tests/fixtures/trust/`，与真实物料路径隔离。

## Non-Functional Requirements

- **NFR-1 安全默认**：任何解析错误、schema 偏差、摘要不符、签名/阈值不符、版本回滚均 fail-closed；私钥物料永不进入 CI 日志、工作流 inputs 或仓库。
- **NFR-2 可审计性**：所有安全状态变更（root 更新、接受发布、降级、安全例外、legacy onboarding、撤销更新、Rekor 树水位）落入 `audit.jsonl`，条目结构化、只追加、可被 `--trust-status` 读取。
- **NFR-3 性能**：验证仅对发布资产做一次顺序哈希；10 个资产、百 MB 级 DMG 在常见硬件上 30 秒内完成（不含网络）。
- **NFR-4 可维护性**：加密原语集中在单一引擎模块并以 RFC/NIST 官方向量测试；信封/schema 版本化（`spec_version`/`schema_version`），未知字段对 `schema_version=1` 严格拒绝。
- **NFR-5 隐私**：产品默认路径零网络、零遥测；在线刷新与 Rekor 验证仅由用户显式触发，不发送机器标识。
- **NFR-6 一致性**：所有 JSON 输出确定性；工作流在 ubuntu/macos/windows 上对同一输入产出字节一致的 manifest/SBOM。

## Constraints

- **Technical**: 仅标准库（产品侧）；Python 3.9 语法兼容；Ruff 规则集 E4/E7/E9/F/I/B、line-length 100；coverage 门槛 81%（既有配置）；Windows 路径/ACL 测试约束；不修改既有发布资产命名。
- **Business**: 真实密钥仪式需维护者线下执行；本环境无法也不允许生成真实主密钥或发布真实新版本；SignPath 申请状态不受影响。
- **Dependencies**: CI 侧允许临时使用 `sigstore-python` 作为 Rekor 校验 oracle（不进入产品运行时、不进入 requirements）；Rekor 公共服务与 GitHub API 在发布工作流中可用。

## Assumptions

- 维护者在首个签名版本前完成：air-gap 生成 root+release 密钥、多渠道公布 root 指纹、设置 `first_signed_version`、提交 root.1 与 revocations.1、生成并提交受信 Rekor 公钥；runbook 在 SECURITY.md / CODE_SIGNING_POLICY.md 中给出。
- 首个签名版本 > 0.6.0；签名线之前的所有历史版本永不具有签名 manifest，因此水位建立后它们天然无法通过"签名发布"渠道（旧资产直接运行属 Non-Goal 边界）。
- Rekor hashedrekord 与 SET/inclusion 的确切字节格式以实现期对公共/staging 实例的实测和 sigstore-python oracle 为准；schema 留版本字段。
- GitHub draft release 可在签名物料齐备前长期保持 draft，且签名物料可经 main-only dispatch 上传后再公开。

## Acceptance Criteria

### AC-1: 签名 manifest 绑定全部发布资产
- **Type**: `rule`
- **Given**: 一个用 fixture release 密钥签名的 stable release manifest 及其资产目录
- **When**: 分别篡改任一资产字节、替换 SHA256SUMS、改动 manifest 中任一 digest/size/字段后重新提供
- **Then**: 验证器对每一种篡改均非零退出、指明不匹配项、不更新本地水位
- **Pass Condition**: 上述全部篡改场景在测试中被拒绝；未篡改基线通过
- **Evidence**: `tests/` 新增端到端测试（参数化篡改矩阵）通过记录

### AC-2: 源码 commit 与构建器绑定
- **Type**: `rule`
- **Given**: manifest 含 source（commit/tag object/repo）与 builder（workflow SHA/runner/工具链/桌面 build-manifest digest）
- **When**: commit 与 tag peeled commit 不符、build-manifest 内容 digest 不符、工具链字段缺失
- **Then**: 离线模式即拒绝；在线模式额外拒绝远端 tag 不一致
- **Pass Condition**: 三类不符各有拒绝测试；一致基线通过
- **Evidence**: 测试输出与 manifest 样例 fixture

### AC-3: 纯标准库 Ed25519 正确性
- **Type**: `rule`
- **Given**: 引擎 Ed25519 实现
- **When**: 运行 RFC 8032 Section 7.1 全部官方测试向量（SIGN/VERIFY 各 1024/若干向量）及信封负例（错误 keyid、损坏签名、threshold 不足、非规范 JSON）
- **Then**: 全部向量通过，负例全部拒绝
- **Pass Condition**: 向量测试通过；`sys.modules` 层面证明引擎仅 import 标准库
- **Evidence**: 测试文件与运行输出

### AC-4: root 引导与密钥轮换
- **Type**: `rule`
- **Given**: root v1（release key A）→ root v2（退役 A、登记 release key B），分别存在 A、B 签名的两个 release
- **When**: 客户端按 v1→v2 更新后验证 A 签的旧 release 与 B 签的新 release；再投喂旧 root v1 试图回滚
- **Then**: 两个 release 均通过；root 回滚被拒绝并审计；缺失旧 root 签名的 v2 被拒绝
- **Pass Condition**: 轮换、旧签名兼容、root 防回滚三条规则均有测试证据
- **Evidence**: 轮换端到端测试

### AC-5: 三类撤销与紧急传播
- **Type**: `rule`
- **Given**: root 签名 revocations 撤销某 release keyid、某版本、某资产 sha256
- **When**: 验证被撤密钥签名的 manifest、被撤版本、含被撤资产的目录；分别用 release 附带副本、仓库路径模拟、`--revocations-file` side-load、低版本撤销文档投喂
- **Then**: 三种撤销均 fail-closed；三条离线/随附渠道均可生效；低版本撤销文档被拒；缺失历史撤销项的文档被拒；过期文档只警告不放宽
- **Pass Condition**: 覆盖矩阵全部通过
- **Evidence**: 撤销矩阵测试

### AC-6: 防回滚水位与显式降级 override
- **Type**: `rule`
- **Given**: 信任目录已接受 sequence=5 的版本
- **When**: 验证 sequence=4（未撤销）：无参数、带 `--allow-downgrade` 精确版本+reason、错误版本、缺 reason；再验证被撤销版本的普通 override 与 `--accept-revoked`
- **Then**: 无参数拒绝；正确 override 放行且审计含 UTC 时间/from/to/manifest hash/reason；错误用法拒绝；被撤版本普通 override 拒绝、显式安全例外放行并产生持续警告状态；首次使用（无水位）TOFU 成功
- **Pass Condition**: 全部分支测试通过；audit.jsonl 条目字段完整
- **Evidence**: 水位/审计测试

### AC-7: Rekor 透明日志锚定
- **Type**: `rule`
- **Given**: 签名 manifest 的 hashedrekord 条目录制 fixture（body、SET、inclusion proof、checkpoint、Rekor 公钥）
- **When**: 纯标准库验证器校验：body hash↔manifest、publicKey↔签名者、SET ECDSA 签名、RFC 6962 inclusion；篡改任一项；投喂更小 tree size；CI 中以 sigstore-python 对同一真实/staging 条目交叉验证
- **Then**: 合法条目通过且与 oracle 结论一致；篡改/小树拒绝；离线默认路径不要求该环节
- **Pass Condition**: fixture 全绿、oracle 一致性脚本在 CI 通过（可用 staging）；无网络测试证明默认路径零 socket
- **Evidence**: 录制 fixture、CI 步骤日志、测试输出

### AC-8: 离线、零依赖、跨平台
- **Type**: `rule`
- **Given**: 引擎、验证器、签名工具
- **When**: 在断网夹具（禁止 socket）下于 Python 3.9 语法/3.9–3.14 运行时、Windows/macOS/Linux 路径语义下执行默认验证
- **Then**: 不发生任何网络调用；无第三方 import；三平台测试通过
- **Pass Condition**: socket monkeypatch 测试通过；import 审计测试通过；CI 三平台矩阵绿
- **Evidence**: CI 矩阵结果与测试记录

### AC-9: 双 SBOM 确定性生成与绑定
- **Type**: `rule`
- **Given**: 当前仓库（含 package-lock.json / Cargo.lock / requirements-build.txt）
- **When**: 连续两次生成 SPDX 2.3 与 CycloneDX 1.6 SBOM；删除/替换某锁定依赖记录后再生成
- **Then**: 两次字节一致；manifest 中 SBOM digest 命中；组件集合覆盖声明的 CLI/scenarios 与 npm/crate/pip 构建组件；篡改导致 digest 不符被验证器拒绝
- **Pass Condition**: 确定性、覆盖、拒绝三类测试通过
- **Evidence**: SBOM 测试与样例输出

### AC-10: 离线签名工具跨平台且防误放私钥
- **Type**: `rule`
- **Given**: keysmith_signing.py 全部子命令
- **When**: 在三平台运行 keygen/root-init/root-rotate/sign-manifest/sign-index/revoke/rekor-submit（后者用本地 mock 服务器）；尝试把私钥输出到仓库目录
- **Then**: 功能正确、产物互验通过；仓库目录输出被拒；fixture 密钥与真实路径隔离
- **Pass Condition**: 子命令级测试在三平台 CI 通过；仓库中不存在任何非 fixture 私钥（扫描测试）
- **Evidence**: 工具测试 + 密钥扫描测试

### AC-11: 发布流程"无签名不发布"
- **Type**: `rule`
- **Given**: first_signed_version 之后的 tag（用临时 policy/fixture 模拟）
- **When**: 走发布工作流：未提供签名物料、提供错误签名、物料齐全三种情况
- **Then**: 前两者 Release 保持 draft/工作流失败；第三者独立复核摘要+签名+Rekor+tag 后公开；first_signed_version 之前 tag 的既有行为不变；已发布 release/tag/资产仍不可覆盖
- **Pass Condition**: 工作流脚本化逻辑（可本地用 gh api 契约/mock 演练的 Python 部分）测试覆盖三种分支；YAML 通过现有 action 钉版审查
- **Evidence**: 工作流测试（如可执行脚本被抽出为 Python 以便单测）与 YAML diff

### AC-12: 旧版本升级兼容
- **Type**: `rule`
- **Given**: 模拟 v0.6.0（未签名线）存量用户与空信任目录用户
- **When**: 二者验证首个签名版本；签名版本建立后再尝试把旧未签名资产当作签名版本验证
- **Then**: 首签版本正常 TOFU/onboarding 并写 `legacy-onboarding` 审计；旧资产不会被承认为签名发布（不产生错误水位、明确提示其未签名状态）
- **Pass Condition**: 迁移与误认拒绝均有测试
- **Evidence**: onboarding 测试

### AC-13: CLI 本地信任集成
- **Type**: `rule`
- **Given**: 含 accepted 记录的信任目录与 standalone 形态 CLI
- **When**: 运行 `--trust-status`；替换 standalone 文件内容后执行 `--yes`；在源码树形态运行；触发 legacy onboarding
- **Then**: 状态输出字段完整；篡改文件在部署命令 fail-closed；源码树仅信息提示；onboarding 一次成功并审计；无新增网络代码
- **Pass Condition**: 新增 CLI 测试通过；既有 codex-instruct 测试零回归；网络 import 审计通过
- **Evidence**: pytest 输出

### AC-14: fail-closed 安全设计质量
- **Type**: `rubric`
- **Dimension**: 面对畸形输入、未知 schema、部分缺失文件、并发/中断（原子写）、同渠道替换、降级/撤销竞态时的默认安全性与最小信任面
- **Scale**: 1-5
- **Anchors**: 1 = 存在可绕过签名/水位的路径或崩溃即放行；3 = 主路径 fail-closed 但边界（并发、畸形元数据、TOFU）处理粗糙；5 = 全部边界显式建模、状态写入原子可恢复、每类失败有测试
- **Pass Threshold**: >= 4
- **Evidence**: 负例测试集合、代码评审、中断/并发测试

### AC-15: 操作可用性与信息质量
- **Type**: `rubric`
- **Dimension**: 验证器/签名工具的错误信息可行动性（指明失败层、资产、期望/实际指纹）、`--json` 机器输出、维护者 runbook 可照做（密钥仪式、轮换、紧急撤销时限）、用户安装指引清晰度
- **Scale**: 1-5
- **Anchors**: 1 = 报错晦涩、无 runbook；3 = 主流程可独立照做但应急流程缺失；5 = 普通用户与值班维护者均可凭文档独立完成安装验证、轮换、紧急撤销
- **Pass Threshold**: >= 4
- **Evidence**: 文档评审 + 按 runbook 盲走演练记录

### AC-16: 用户与维护者文档更新
- **Type**: `rule`
- **Given**: README.md / README.en.md / docs/agent-install.md / SECURITY.md / CODE_SIGNING_POLICY.md
- **When**: 审查安装流程、威胁模型与指纹多渠道发布、密钥仪式/轮换/紧急撤销 runbook、发布控制变更
- **Then**: 安装指引改为"获取 root 指纹 → 验证器核验（含可选 Rekor）→ 再运行"；agent-install 中英指令同步；政策文档准确描述 draft/签名门、离线密钥与 SignPath 的关系，不夸大为 Apple/Authenticode 签名
- **Pass Condition**: 五处文档更新且与实现一致；保留现有 WINDOWS_FRESH_DEPLOYMENT_POLICY 标记机制
- **Evidence**: 文档 diff 与一致性检查

### AC-17: 测试与质量门禁
- **Type**: `rule`
- **Given**: 全部新增与既有测试、Ruff、coverage
- **When**: 在 CI 矩阵（3.9/3.14 ubuntu+macos，3.10/3.12/3.14 windows）运行
- **Then**: 新增测试全绿、既有测试零回归、Ruff 通过、coverage 不低于既有门槛
- **Pass Condition**: 本地与 CI 全绿；新增密码学/SBOM/信任逻辑纳入 coverage 统计
- **Evidence**: pytest/ruff/coverage 输出

## Open Questions

- [ ] 首个签名版本号（预计为 v0.7.0；由维护者在密钥仪式后于 `trust/policy.json` 声明）——不影响本次实现，默认 null。
- [ ] root threshold 初始值（runbook 默认 1-of-1 并说明多签升级路径；schema 已支持 threshold>1）。
- [ ] revocations 有效期长度（runbook 默认 30 天；实现只强制字段存在与单调逻辑）。
