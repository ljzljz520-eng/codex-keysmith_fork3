# Release 签名信任体系 - 实现计划

> 说明：产品侧代码（引擎/验证器/签名工具/SBOM 生成器）一律纯标准库、Python 3.9 兼容（`from __future__ import annotations`，避免运行时 PEP 604）；Ruff 现有规则集与 100 列宽；实现与测试同任务交付。

## Task 1: 仓库信任策略与元数据 schema 基础设施
- **Status**: `completed`
- **Priority**: high
- **Depends On**: None
- **Completion Evidence** (2025-07-01):
  - 新增 `trust/policy.json`（first_signed_version=null、两发布线、渠道/Rekor 模板、revocations 默认 30 天）与 `trust/{root,revocations,releases}/.gitkeep` 空物料目录。
  - 新增 `scripts/keysmith_trust.py`：TrustError 异常体系（含退出码常量 10/11/12/13/14/15）、规范 JSON、信封 make/load 严格校验、ed25519 keyid 派生、schema 守卫、policy fail-closed 加载、跨平台安全文件名、O_NOFOLLOW 常规文件读取、0700/0600 原子写、audit.jsonl 只追加、流式 sha256。
  - 新增 `tests/test_trust_metadata.py`（17 测试全绿）：TR-1.1 规范字节确定性/差异/非 ASCII；TR-1.2 policy 全负例 fail-closed + 真实 trust 目录无物料隔离断言；TR-1.3 ast import 审计证明仅 stdlib + py_compile 3.9 通过。
  - 本地：`python3.9 -m pytest tests/test_trust_metadata.py` 17 passed；全量 `pytest tests` 1218 passed（2 个失败为既有 OPENAI_BASE_URL 网络环境用例，与本改动无关）；ruff 全过。
- **Description**:
  - 新增 `trust/policy.json`（product 常量、发布线定义、`first_signed_version: null`、rekor 端点与渠道 URL 模板、schema/spec 版本约定）与目录结构（`trust/root/`、`trust/revocations/`、`trust/releases/`），真实签名物料留空；fixture 物料隔离在 `tests/fixtures/trust/`。
  - 在 `scripts/keysmith_trust.py` 中定义统一信封 `{"signed", "signatures"}` 与规范序列化（UTF-8、`json.dumps(ensure_ascii=False, indent=2, sort_keys=True)+"\n"`)、keyid 派生（`ed25519:` + 32 字节公钥 sha256 hex）、schema 版本守卫（未知字段/未知 `_type` 严格拒绝）、TrustError 异常体系。
  - policy 加载（可被 `--trust-policy` 覆盖以便测试）、跨平台安全路径辅助（复用仓库现有符号链接/保留名/大小写冲突规则的同源逻辑或等价实现）。
- **Acceptance Criteria Addressed**: AC-8
- **Test Requirements**:
  - `rule` TR-1.1: 规范字节对同一对象两次生成字节一致、键排序严格、非 ASCII 稳定；任意结构差异（键序、空白、类型）产生不同字节——证据：tests/test_trust_metadata.py
  - `rule` TR-1.2: 政策文件缺失/畸形/未知发布线/非 null 但非 semver 的 first_signed_version 全部 fail-closed；fixture 与真实路径严格隔离——证据：同文件测试
  - `rule` TR-1.3: 模块仅 import 标准库（ast 扫描可分发模块 import 集合），Python 3.9 语法编译通过——证据：测试 + py_compile

## Task 2: 纯标准库 Ed25519 原语与签名信封
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Completion Evidence** (2025-07-01):
  - `scripts/keysmith_trust.py` 新增 RFC 8032 Ed25519（纯 stdlib big-int 扩展坐标实现，base-point 4-bit window 加速，cofactored [8]S·B=[8]R+[8]k·A 验签）：generate/public/sign/verify、secret container、grouped 指纹、OpenSSH blob/line/SHA256 指纹、seal/add/verify_role_envelope threshold 判定（未授权签名忽略、threshold 不足拒）。
  - 新增 `tests/test_trust_crypto.py`（17 测试）：TR-2.1 覆盖 RFC 8032 §7.1 全部 5 个发布向量（TEST 1/2/3/1024 含 1023 字节消息/SHA(abc)），1024 random/cyclic 调度与 switch 逆序重放，末三元组已经 OpenSSL(Node crypto) 独立预言机逐签名交叉确认（random: seed ad1c3398…/pk aa02c674…；cyclic: seed 0e5d2a24…/pk c64cf4de…）；错公钥/错消息/翻转 R/S/S≥L/非曲线点/长度全拒。
  - TR-2.3 OpenSSH 行与 `ssh-keygen -lf` 指纹完全一致（SHA256:bbXpuKG6…，条件执行测试）。
  - 1024×3 调度 7.1s（Python 3.9.6, M 系列）；ruff、py_compile 全过；TR-2.2 三平台×3.9/3.14 留 CI 矩阵。
- **Description**:
  - 在引擎中实现 RFC 8032 Ed25519 keygen/sign/verify（约 200–300 行，含坐标/压缩/2^52 limbs 实现）；密钥容器（seed/secret/public hex JSON）、指纹分组打印；verify-only 失败不区分时序但必须恒定拒绝任何非 32 字节输入。
  - 信封签名/验签：多签名追加、threshold 判定、keyid 绑定、规范负载固定；签名 hex 编码。
  - 提供与 `ssh-keygen` 对应公钥/指纹表示的导出辅助（仅文档互核用途：raw hex 与 openssh 行格式）。
- **Acceptance Criteria Addressed**: AC-3, AC-8
- **Test Requirements**:
  - `rule` TR-2.1: 通过全部 RFC 8032 §7.1 测试向量（TEST 1..3、1024 随机对、1024 链、1024 switch）；错公钥/错消息/损坏签名/非规范负载均拒——证据：tests/test_trust_crypto.py
  - `rule` TR-2.2: 自签自验在三平台、Python 3.9/3.14 一致（CI 矩阵）——证据：CI
  - `rule` TR-2.3: openssh 格式指纹与 `ssh-keygen -lf` 一致（有 ssh-keygen 时执行；无时以固定向量跳过不弱化 RFC 向量）——证据：条件测试

## Task 3: root / release-index / revocations 角色元数据逻辑
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 2
- **Completion Evidence** (2025-07-01):
  - `scripts/keysmith_trust.py` 新增约 710 行纯函数元数据层（仅加 `re`/`datetime` 两个 stdlib import）：SemVer 2.0 比较（含 prerelease 排序）；root schema（角色表/密钥字典严格一致、keyid 必须派生自公钥、禁未引用密钥、threshold≤key 数、Rekor PEM 条目形状）；`verify_root_document`（v1 自签引导；vN+1 必须版本恰好 +1 且旧 root threshold，继任者自签可附加但不计入旧角色）；`ensure_root_not_rolled_back`。
  - release manifest 完整 schema（product/line/version/tag 交叉规则、commit 40|64 hex、tag_object 20B、builder 九字段精确集合、desktop-beta 强制 build_manifests、artifacts 非空、sboms 恰好 2 份）；release-index 两线独立、sequence 从 1 连续、version/hash 去重、Rekor uuid+log_index 成对可空；`append_index_entry`/`verify_index_against_manifest`（篡改抛 DigestError）/`verify_index_signature`（release 角色）。
  - revocations schema（三类条目精确字段、严重度枚举、范围不倒置、同线范围禁重叠、key/artifact 去重）；`revoked_key_entry`/`revoked_artifact_entry`/`revoked_release_entry`（精确+闭区间边界+跨线隔离+prerelease 语义）；`revocations_is_expired` 软信号；`ensure_revocations_cumulative`（v1 起版、版本只 +1、三类历史条目按完整身份累积，缺失抛 RevocationError）；`verify_revocations_signature`（revocation 角色 threshold，release key 不可代签）。
  - `tests/test_trust_metadata.py` 新增 20 测试（模块共 37 测试全绿）：TR-3.1 root v1 自签/version≠1/无签/外部 key 伪造、轮换成功路径（旧 key 签 / 旧+新都签）、3-key threshold 矩阵（1 旧拒、1 旧+1 新拒、2 旧过）、跳版/回滚、角色表六类畸形、Rekor 条目五负例；TR-3.2 合法文档往返、schema 负例（重复/范围倒置/严重度/非法 semver/布尔类型/重叠 vs 相邻 vs 跨线）、范围边界与 prerelease、过期边界、累积性（跳版/三类丢项/改 reason 即丢身份）、revocation 角色 threshold 与越权；TR-3.3 manifest tag/schema、index 两线追加与 version 递增、重复版本/sequence 缺口/篡改索引、index schema 负例、manifest 篡改 DigestError、release 角色 threshold 与 revocation 越权。
  - 本地：`pytest tests/test_trust_metadata.py tests/test_trust_crypto.py` 54 passed；全量 `pytest tests` 1255 passed（2 失败为既有 OPENAI_BASE_URL 网络用例，与本改动无关）；ruff 全过、py_compile 3.9 通过。
- **Description**:
  - root v(N)→v(N+1) 轮换验证：新 root 必须由旧 root threshold 签名（可选附新自身签名）；角色表与密钥字典一致性；release/revocation 角色解析；root 版本单调与回滚拒绝；Rekor 公钥 PEM 条目（多日志/分片支持）。
  - release-index：构建/追加/验签（release 角色）、每发布线 (version, sequence, manifest hash, rekor 定位) 列表、index 自身 version 单调；检测重复 sequence、错误 manifest hash、缺失条目。
  - revocations：构建（只增累积）、root 签名验证、version 单调、过期标记（软警告）、按 keyid/发布线+版本/版本范围/资产 sha256 匹配；新文档缺历史未过期项即拒。
  - 判定函数纯函数化，便于单元测试与验证器复用。
- **Acceptance Criteria Addressed**: AC-4, AC-5
- **Test Requirements**:
  - `rule` TR-3.1: root 轮换矩阵（合法轮换、旧 root 未签、threshold 不足、回滚投喂、release key 退役/新增、旧 A 签 release 在 root v2 下仍可验、B 新签可验）——证据：tests/test_trust_metadata.py
  - `rule` TR-3.2: revocations 全部分支（三类撤销命中、低版本拒、缺累积项拒、过期仅警告、版本范围边界）——证据：同文件
  - `rule` TR-3.3: index 追加/重复 sequence/不一致 hash/签名者非 release 角色全部正确判定——证据：同文件

## Task 4: 本地信任状态库（水位 / 审计 / 原子持久化）
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 3
- **Completion Evidence** (2025-07-01):
  - `scripts/keysmith_trust.py` 新增状态库段（约 380 行，零新第三方 import）：`ensure_trust_layout`（拒符号链接祖先 + 0700）、`empty_state`/`validate_state`（精确 schema：schema_version=1、两发布线、accepted 四字段、rekor_tree_size 非负、security_exceptions 四字段且 (version,hash) 唯一；任何结构缺陷统一归一为 StateError fail-closed）、`load_state`/`save_state`（缺失即 TOFU 空态；规范字节 + 既有原子写 0600）、root/revocations/release-index 三类缓存信封读写（结构校验 + `_type` 绑定，未知 kind 拒）。
  - 纯判定：`evaluate_acceptance`（TOFU/upgrade/reinstall/downgrade-override/security-exception/组合六类动作；降级须 `allow_downgrade` 精确匹配版本+非空书面 reason；被撤版本须 entry 允许例外 + `accept_revoked` 精确版本 + reason；同版本不同 hash 拒、新 semver 配旧 sequence 拒；两 override 可组合且必须同时满足）、`commit_acceptance`（不可变更新 + 例外只在首次落盘、重复授权标记 previously_granted）、`record_tree_size`（Rekor tree size 逐线单调，回滚抛 RekorError）、`decision_audit_entry`/`legacy_onboarding_audit_entry`/`record_trust_event`。
  - 新增 `tests/test_trust_state.py`（16 测试全绿）：TR-4.1 水位矩阵（TOFU 审计字段完整、升级/重装/同版本异 hash/版本升 sequence 降、降级三负例+精确 override 放行+审计、安全例外四负例+持久标记+重复授权不复制、降级×撤销组合、两线独立）；TR-4.2 幂等往返/POSIX 0700+0600/os.replace 故障注入旧状态完好无残留临时文件/10 类畸形状态 fail-closed/state 符号链接拒/缓存信封错 `_type` 拒/`CODEX_KEYSMITH_TRUST_DIR` 重定位；TR-4.3 只追加前缀保持、非对象/空行 fail-closed；TR-4.4 tree size 逐线单调、legacy-onboarding 条目校验、拒绝不改变已落盘状态。
  - 本地：`pytest tests/test_trust_state.py` 16 passed；全量 `pytest tests` 1271 passed（2 失败为既有 OPENAI_BASE_URL 网络用例，与本改动无关）；ruff 全过、py_compile 3.9 通过。
- **Description**:
  - 实现 `~/.codex-keysmith/trust/` 布局：缓存 root、revocations、index、`state.json`（每线 accepted version/sequence/manifest hash/时间、tree size、活动安全例外）、`audit.jsonl` 只追加。
  - 原子写（同卷 temp + replace，Windows 用 os.replace；权限 0700/0600；best-effort fsync；读时校验所有权/类型，拒符号链接）。
  - 水位比较（semver + 每线 sequence）、降级判定、override 与安全例外记录、TOFU 初始化、legacy-onboarding 事件；审计条目结构化（事件类型、UTC 时间、from/to、manifest hash、reason）。
  - `--trust-dir` 重定位支持。
- **Acceptance Criteria Addressed**: AC-6, AC-12, AC-14
- **Test Requirements**:
  - `rule` TR-4.1: 水位矩阵（TOFU、升级、降级拒、精确 override 放行/错版本/缺 reason 拒、审计字段完整、安全例外持续标记）——证据：tests/test_trust_state.py
  - `rule` TR-4.2: 原子性/抗中断（写中模拟异常无半文件、重复执行幂等）与权限（POSIX 0700/0600；Windows 跳过权限断言但验证文件类型）——证据：同文件
  - `rule` TR-4.3: audit.jsonl 只追加不可改写既有前缀（重放/损坏行 fail-closed）——证据：同文件
  - `rubric` TR-4.4: 并发与状态破坏恢复质量；scale 1-5；anchors 1=损坏即放行/覆盖审计，3=主流程安全但错误状态提示差，5=所有畸形状态 fail-closed 且信息可行动；threshold >= 4；证据：负例测试评审

## Task 5: P-256 验签、RFC 6962 Merkle 校验与 Rekor 条目离线验证
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 2
- **Description**:
  - 纯标准库实现 ECDSA P-256 verify（P-256 曲线参数、SHA-256、DER/raw 签名解析、公钥 PEM 解析，不实现签名）；使用 RFC 4754 §8 向量验证。
  - RFC 6962 leaf hash / inclusion proof 校验（含 generalized proof、边界 index/size 拒绝）。
  - Rekor hashedrekord 解析（base64 body、spec/data.hash/signature.publicKey 与 envelope 一致性）、SET 载荷重构与验签、checkpoint signed-note 核验；tree size 水位接入 Task 4。
  - 所有网络交互隔离在可注入的 fetcher 之后；默认零 socket。
  - 录制真实公共 Rekor hashedrekord 条目为 fixture（实现期用签名工具向公共 Rekor 提交一条无害 fixture manifest，保存 entry UUID/body/SET/proof/checkpoint 于 `tests/fixtures/trust/rekor/`），用于永久离线重放。
- **Acceptance Criteria Addressed**: AC-7, AC-8
- **Test Requirements**:
  - `rule` TR-5.1: RFC 4754 P-256 验签向量通过；DER 畸形/非曲线点/错误哈希拒绝——证据：tests/test_trust_crypto.py
  - `rule` TR-5.2: Merkle inclusion 合成证明（多 leaf、边界 index、篡改任一层 hash/rootSize）判定正确——证据：tests/test_rekor_verify.py
  - `rule` TR-5.3: 录制条目完整通过（SET/checkpoint/inclusion/body 绑定/公钥一致）；逐字段篡改（body、SET、proof、treeSize、公钥）均拒；较小 tree size 拒——证据：同文件 + 录制 fixture
  - `rule` TR-5.4: 默认验证路径在 socket 禁止夹具下零网络调用——证据：monkeypatch 测试
- **Completion Evidence**:
  - 引擎（[scripts/keysmith_trust.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/keysmith_trust.py)，Task 5 段落）：ECDSA P-256 **只验不签**（点运算/on-curve/SPKI 解析，双曲线 OID `1.2.840.10045.3.1.7` 与 `1.3.132.0.34`，DER/raw 64B 双签名格式，支持 prehashed 直验 raw digest）；RFC 6962 generalized §2.1.2 inclusion；hashedrekord v0.0.1 严格解码（Ed25519 签 hex 文本 + P-256 签 raw 32B digest 双 scheme）、SET 验签（兼容 verification/proof 两位置、二选一）、分片 proof.logIndex、RFC 9162 checkpoint 三行 note 解析，且**用受信日志 P-256 公钥核验 checkpoint 签名行**（实测 Sigstore 签名格式：`<logID 前 4 字节><DER ECDSA 签名>`，签名消息为三行 note + 单个换行；未知共同签名行可共存，受信密钥必须签名），从而绑定 tree size/root 不可篡改。
  - 测试：[tests/test_trust_crypto.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_trust_crypto.py) 23 passed（TR-5.1：RFC 4754 §8.1 发布向量、DER/raw/双 OID、错误消息/公钥/畸形 SPKI 与签名全拒、logID=SHA256(DER)）；[tests/test_rekor_verify.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_rekor_verify.py) 27 passed：TR-5.2 用 transparency-dev/merkle **5 条官方锚向量**（size 1/3/5/8）+ 独立朴素递归参考对 size 1–40 全索引穷举、每层 proof/leaf 篡改与越界/过长过短/31B/bool 全拒；TR-5.3 真实录制条目全链路通过且 binding 与 fixture metadata 一致、Ed25519/P-256(DER+raw) 合成条目（含 size 1/3/7/8 边界与 legacy SET-in-proof、未知共同签名行）、15 项逐字段篡改矩阵全拒（body digest/制品签名/SET/proof hash/treeSize/checkpoint size+root+去签名/rootHash/logID 错钥/logIndex/proof index/缺 checkpoint/SET 双位置/未知字段）；TR-5.4 引擎源码无 socket/urllib/http/ssl/requests import，且 monkeypatch socket 与 urlopen 后真实 fixture 离线重放。
  - 真实 fixture（永久离线重放）：[tests/fixtures/trust/rekor/](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/fixtures/trust/rekor) 含日志公钥、完整真实条目（UUID `108e9186e8c5677abb479924e76e16c239c0d392796c5c672ffa3d3f192807f4cc100d02168caf6d`，全局 logIndex 3168565445、分片 3046661183、treeSize 3046791283、26 个 proof hashes、SET、checkpoint 签名）、P-256 制品签名者公钥与 metadata；由引擎真实验证通过。实测确认 Rekor 生产锚定必须 P-256 签 raw digest（Ed25519 被公共 Rekor 拒，hash 算法只允许 SHA-512）。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check scripts/keysmith_trust.py tests/test_trust_crypto.py tests/test_rekor_verify.py` 全过；`python3 -m py_compile` 通过；全量 `/tmp/keysmith-qc/bin/python -m pytest -p no:cacheprovider -q tests` → **1304 passed, 25 skipped**，仅 2 个既有 `test_prompt_bank_regression.py` 因缺 `OPENAI_BASE_URL` 失败（与本任务无关）。

## Task 6: 确定性双格式 SBOM 生成器
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 1
- **Description**:
  - 新增 `scripts/generate_sbom.py`：纯标准库输出 SPDX 2.3 JSON 与 CycloneDX 1.6 JSON。
  - CLI 线：仓库固定发布文件集（与 build_release ARCHIVE_FILES 同源）+ scenarios/fixture_packs 文件 sha256、MIT license、构建器/工具链元数据；桌面线：解析 `gui/package-lock.json`（含嵌套依赖、版本、license、integrity）、`gui/src-tauri/Cargo.lock`、`gui/requirements-build.txt`，并纳入每平台 build-manifest 引用。
  - 确定性：排序、固定时间戳字段（不写生成时刻，写可复现的 release 标识）、两次运行字节一致；解析失败/缺字段 fail-closed。
- **Acceptance Criteria Addressed**: AC-9
- **Test Requirements**:
  - `rule` TR-6.1: 两次生成字节一致（SPDX 与 CDX 各一），JSON 合法且 schema 关键字段（spdxVersion/cdxSpecVersion、组件数、关系/依赖、checksums）齐全——证据：tests/test_sbom.py
  - `rule` TR-6.2: 组件覆盖断言（抽查 npm 包、crate、PyInstaller 条目与固定 CLI 文件存在且版本正确）；篡改 lock 文件后摘要变化/失败——证据：同文件
  - `rule` TR-6.3: 三平台路径安全、3.9 兼容、仅标准库——证据：CI + import 审计
- **Completion Evidence**:
  - 新增 [scripts/generate_sbom.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/generate_sbom.py)（纯标准库，仅复用 keysmith_trust 与 build_release.ARCHIVE_FILES 常量）：CLI/API 双入口；不读时钟/环境/网络，`issued_at`/commit/line/version 全部显式传入；SPDX 2.3（DESCRIBES/CONTAINS/DEPENDS_ON 关系、SHA256/SHA512 checksums、purl externalRef、builder annotation）与 CycloneDX 1.6（uuid5 确定性 serialNumber、file/library 组件、cargo 依赖边、dev 依赖 scope=optional、builder properties）双文档；清单覆盖固定 38 个 ARCHIVE_FILES（直接 import 同源常量）+ scenarios/、fixture_packs/ 全部常规文件（拒符号链接）；桌面组件解析 npm lockfileVersion 3（含嵌套多版本、sha512 integrity 严格 base64/长度校验）、Cargo.lock v3/v4（自写严格块解析器、checksum 64 hex、依赖边、name-only 歧义剔除、零包 fail-closed）、requirements-build.txt（仅接受 name==version）。
  - 真实仓库冒烟：对当前 checkout 生成成功（111 个文件、749 个组件：276 npm / 471 cargo / 1 pypi / 1 本地 crate），两次运行产物目录 **byte-identical**（diff -r 全等），冒烟目录已删除。
  - 测试 [tests/test_sbom.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_sbom.py) 17 passed：TR-6.1 schema 关键字段/双格式字节一致/commit 变化改变文档与 serial/写出 0o644 资产且记录可重算；TR-6.2 npm（左填充、嵌套 string-width 4.2.3+7.2.0、dev optional）、cargo（adler2 sha256、本地 crate memchr 无 purl、依赖边 SPDX+CDX 双断言）、PyInstaller 6.16.0 覆盖，篡改 checksum/版本反映到文档，7 类畸形锁输入（sha1 integrity/32B integrity/缺 version/lockfileVersion 2/无 package 块/坏 checksum/`>=` 与 URL pip 行）fail-closed，桌面三锁缺一即拒、无 gui 树可跳过；TR-6.3 符号链接拒、SPDX/CDX 标识符碰撞 fail-closed、缺固定文件/坏 semver/坏时间戳/坏 commit 拒、CLI 成功与退出码 1、源码无 socket/urllib/datetime.now/time.time。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check scripts/generate_sbom.py tests/test_sbom.py` 全过；`python3 -m py_compile` 通过；全量 → **1321 passed, 25 skipped**，仅 2 个既有 `test_prompt_bank_regression.py` 因缺 `OPENAI_BASE_URL` 失败（与本任务无关）。

## Task 7: stable 线未签名 manifest 生产接入 build_release
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 3, Task 6
- **Description**:
  - build_release.py 新增显式开关（如 `--emit-trust-artifacts` + `--sequence N` + builder 信息注入 `CODEX_KEYSMITH_BUILDER_INFO`）：默认行为与产物集合（5 资产）**逐字节不变**；开启后在同目录额外产出 `release-manifest.unsigned.json`、两份 SBOM、`verify-release-v<tag>.py`（引擎+verify CLI 合成，见 Task 10），manifest.artifacts 覆盖 FR-4 stable 全集（含 SHA256SUMS 自身 digest），source 取已验证 commit/annotated tag object，builder 字段来自 CI 注入或显式 `local`。
  - 未签名 manifest 经严格 schema 校验写出；sequence 由调用方负责（CI 从最新 index 推导，测试显式传入）。
  - 新脚本加入 ARCHIVE_FILES（keysmith_trust/verify_release/keysmith_signing/generate_sbom）。
- **Acceptance Criteria Addressed**: AC-2, AC-8, AC-11
- **Test Requirements**:
  - `rule` TR-7.1: 默认构建产物集合/字节与现状一致（既有 test_release_artifacts 全绿即证据）；开关开启后产物齐全且 manifest 摘要逐字段可重算——证据：tests/test_release_manifest.py
  - `rule` TR-7.2: builder/source 字段缺失或不一致（坏 commit、缺 workflow sha、坏 sequence）拒绝构建——证据：同文件
  - `rule` TR-7.3: 双构建可复现扩展到新产物（两次 diff 全等）——证据：测试
- **Completion Evidence**:
  - [scripts/build_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/build_release.py) 新增：`TRUST_ARCHIVE_FILES`（generate_sbom/keysmith_signing/keysmith_trust/verify_release 四脚本，**仅开关开启时并入归档源**，默认 5 资产字节零变化）、`--emit-trust-artifacts/--sequence/--issued-at/--builder-info/--source-repo/--required-root-version/--required-revocations-version` CLI；`CODEX_KEYSMITH_BUILDER_INFO` 与 `CODEX_KEYSMITH_SOURCE_REPO` 环境变量注入（CI 用）；builder 严格归一化（5 必填字符串、workflow_sha 40/64 hex、3 可选版本串、build_manifests 名称过 validate_asset_name + 32B hex、未知字段拒绝）；`git rev-parse <tag>^{tag}` 强制 annotated tag object（轻量 tag 拒绝）；未带开关传 trust-only 参数立即拒绝。
  - `_emit_trust_artifacts()` 在 SHA256SUMS 定稿后产出：合成单文件 [verify-release-v\<tag\>.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/verify_release.py)（保留 shebang、注入 MIT 许可头、base64 内嵌 keysmith_trust 引擎替换 `KEYSMITH_TRUST_ENGINE_PAYLOAD = None` 标记、0o755）；SPDX+CDX 双 SBOM（固定文件集=ARCHIVE_FILES∪TRUST_ARCHIVE_FILES∪release notes，桌面锁自动全无跳过；SbomError 包装为 ReleaseError）；manifest 14 字段齐全（artifacts=4 核心资产+SHA256SUMS 自身+合成验证器；sboms 恰好 2 份且 sha256/size 从定稿文件实算），写出前过 `trust.validate_release_manifest`，canonical 渲染（indent=2/sort_keys/尾换行）；新产物复用既有的 staging→no-overwrite 发布→三重 commit 稳定性校验（validated/final/published 均带 extra_source_files）与失败回滚。
  - 占位脚本：[scripts/verify_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/verify_release.py)（携带引擎注入标记，Task 10 实现完整管线）与 [scripts/keysmith_signing.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/keysmith_signing.py)（Task 8 实现）；两者占位直接执行返回退出码 2 并提示后续任务，保证归档/SBOM 源集从本任务起完整且确定，Task 8/10 原地替换。
  - 测试 [tests/test_release_manifest.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_release_manifest.py) 9 passed（独立 importlib 加载、annotated/lightweight tag 双 fixture、完整 scenarios/fixture_packs/真实信任脚本拷贝）：TR-7.1 默认仅 5 资产且 SHA256SUMS 仍只列 4 核心资产；trust 构建 9 产物齐全，manifest 过引擎 schema 且 artifacts/sboms 每个 sha256+size 逐字段重算一致，source 绑定真实 HEAD commit 与 `^{tag}` object，SPDX 2.3/CDX 1.6 可解析，canonical 重渲染字节相等，zip/tar 含四信任脚本且 tar 内 verify_release 保留可执行位，合成验证器 `compile()` 通过且 base64 载荷解码后等于被评审的 keysmith_trust.py、文件 0o755；TR-7.2 轻量 tag/sequence=0/缺 issued-at/非 UTC 时间/缺+坏 workflow_sha/坏 build_manifests digest/缺 builder 对象/未开开关传 trust 参数/坏 source commit(SBOM 层包装)/坏 tag_object(manifest schema 层包装) 全部拒绝；TR-7.3 同目录重复发布幂等且两次输出目录全部 9 文件 byte-identical；另覆盖 CLI env 注入 builder（sequence=7）。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check codex-instruct.py tests scripts` 全过；`python3 -m py_compile scripts/build_release.py scripts/verify_release.py scripts/keysmith_signing.py` 通过；全量 → **1330 passed, 25 skipped**，仅 2 个既有 `test_prompt_bank_regression.py` 因缺 `OPENAI_BASE_URL` 失败（与本任务无关，基线即如此）。
  - 备注：verify-release-v\<tag\>.py 的合成已在本任务落地（含引擎嵌入与许可头），Task 10 只需把占位 verify CLI 替换为完整验证管线；产物名/合成契约测试已先行锁定。

## Task 8: 维护者离线签名工具（密钥/root/轮换/manifest/index/revoke）
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 3, Task 7
- **Description**:
  - 新增 `scripts/keysmith_signing.py`（纯标准库）：`keygen`、`root-init`、`root-rotate`、`release-key add|retire`、`sign-manifest --sequence N`（stamp + 签 + threshold 追加）、`sign-index`（读 index + 新 manifest 累积）、`revoke --kind key|release|artifact`。
  - 防误放：拒绝向含 `.git` 的目录/仓库跟踪路径写私钥（显式 `--i-know-this-is-not-a-repo` 才能覆盖）；私钥文件权限 0600；命令输出不回显 seed。
  - 提供确定性测试密钥派生（从固定测试 seed）供测试与 fixture 生成，工具文档标明仅测试用。
- **Acceptance Criteria Addressed**: AC-4, AC-5, AC-10
- **Test Requirements**:
  - `rule` TR-8.1: 端到端：keygen→root-init→签 manifest→签 index→rotate→新 key 再签→revoke 全链路产物被引擎接受，旧 root/旧签名行为符合 TR-3.1——证据：tests/test_signing_tool.py
  - `rule` TR-8.2: 私钥落盘保护（仓库目录拒、符号链接路径拒、权限断言 POSIX）——证据：同文件
  - `rule` TR-8.3: 仓库密钥扫描：跟踪文件中除 tests/fixtures/trust 外无私钥容器/seed——证据：tests/test_trust_secrets.py
- **Completion Evidence**:
  - [scripts/keysmith_signing.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/keysmith_signing.py) 全量子命令落地（纯标准库、Python 3.9、零网络——无 urllib/socket/http，由测试断言锁定）：`keygen`（--role root/release/revocation、os.urandom、指纹+SSH 风格 fingerprint、0600 secret 容器 + 0644 public sidecar、`--from-seed` 明确标注 TEST ONLY、输出永不回显 seed）、`root-init`（角色/阈值/Rekor PEM 全量指定，seal 后立即 `verify_root_document(v1)` 自检）、`root-rotate`（版本严格 +1、旧 root threshold 签名强制、新 root 密钥可附加自签、角色/阈值/Rekor 全量替换或整体继承、verify_root_document 自检）、`release-key add|retire`（两词命令经 argv 归一化支持；基于 rotate 构造器；单签名低于阈值时拒绝且不写文件）、`sign-manifest`（schema 校验后 seal，`--append-to` 离线阈值追加、同 key 重签拒绝、`--root` 可选阈值复核）、`sign-index`（`append_index_entry` 连续 sequence 累积、可回填 rekor uuid/log_index、root 复核）、`revoke --kind key|release|artifact`（累积携带历史、severity/范围/fixed_version/security_exception 全字段、`validate_revocations`+`ensure_revocations_cumulative` 双闸、revocation 角色密钥签名、root 复核）；统一 `--json` 机器输出与稳定非零退出码。
  - TR-8.1 测试 [tests/test_signing_tool.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_signing_tool.py) 10 passed：完整典礼——keygen×6 → root v1（root 阈值 2、Rekor PEM keyid 断言 `rekor:c0d23d6a...`）→ rel1 签 manifest seq1 + index v1（verify_index_against_manifest 锁定 hash）→ add rel2 单签失败/双签成功(root v2) → root 轮换为 root2+root3（旧阈值 root1+root2 签名 + root3 自签，新角色表下阈值满足）→ retire rel1(root v4) → rel2 签 seq2 + index v2 → rel1 旧签名在 v4 下失效（SignatureError）→ revoke rel1(v1) → 叠加 release 区间撤销(v2，历史 key 撤销保留) → 重叠区间拒绝不写文件；另测 release 阈值 2 的 seal/append 仪式（无 root 可出部分签名、同 key 二次追加拒绝）。
  - TR-8.2：git worktree 内生成私钥默认拒绝、`--i-know-this-is-not-a-repo` 放行；符号链接祖先路径即使带 override 也拒（`reject_symlink_ancestors`）；POSIX 断言 secret 0600/sidecar 0644；capsys 断言 seed 不进 stdout/stderr；同名物料覆盖拒绝；畸形 --from-seed（非 hex/31B/33B）拒绝；JSON 输出可解析。
  - TR-8.3 [tests/test_trust_secrets.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_trust_secrets.py) 3 passed：`git ls-files` 全跟踪文件扫描——任何位置零 PEM 私钥块（6 类 BEGIN ... PRIVATE KEY）、`tests/fixtures/trust/` 外零 `*.key.json`、零完整 Ed25519 私钥容器形状（keytype+seed+public 临近正则，字段顺序无关）；含正/反对照（render_json(make_secret_container) 命中、字段破坏后不命中、手写乱序容器命中）；fixture 的 *.pem 仅含 PUBLIC SPKI。RFC 8032 官方公开向量不在此列（无私钥容器形状）。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check scripts/keysmith_signing.py tests/test_signing_tool.py tests/test_trust_secrets.py` 全过；`python3 -m py_compile` 通过；全量 → **1343 passed, 25 skipped**，仅 2 个既有 `test_prompt_bank_regression.py` 缺 `OPENAI_BASE_URL` 失败（基线无关）。

## Task 9: Rekor 提交客户端（维护者工具子命令）
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 5, Task 8
- **Description**:
  - `keysmith_signing.py rekor-submit`：urllib 构造 hashedrekord v0.0.1 POST 到可配置 `--rekor-url`，处理 409 已存在（搜索取回）、轮询 integratedTime/inclusion proof、写出 `rekor-entry.json`（与验证器输入契约一致）。
  - 网络仅存在于该子命令；支持自定义 CA/超时；用本地 http.server 夹具测试，不打真实网络。
  - 实现期用该命令向公共 Rekor 提交 Task 5 所需录制 fixture（一次性手工步骤，记录命令与 UUID）。
- **Acceptance Criteria Addressed**: AC-7, AC-10
- **Test Requirements**:
  - `rule` TR-9.1: mock 服务器覆盖：成功提交、409 去重回取、轮询直到 inclusion、超时/畸形响应 fail-closed——证据：tests/test_signing_tool.py
  - `rule` TR-9.2: 提交产物可被 Task 5 离线验证器原样接受——证据：跨测试夹具
  - `rule` TR-9.3: 录制 fixture 的 UUID 与提交记录一致（fixture 文件元信息注释）——证据：tests/fixtures/trust/rekor/
- **Completion Evidence**:
  - [scripts/keysmith_signing.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/keysmith_signing.py) 新增 `rekor-submit` 子命令（全工具唯一网络面，urllib/ssl/time 全部函数内懒导入，AST 测试锁定顶层零网络模块、urllib 仅出现在该段）：锚定对象是**已签 manifest 信封的 canonical signed payload**（`trust.signed_payload_bytes` 的 sha256，与验证器口径一致）；`build_hashedrekord_document` 构造 hashedrekord v0.0.1 proposal（digest=64hex、signature.content=DER 签名 base64、publicKey.content=SPKI PEM base64）；`preflight_hashedrekord_document` 在**任何网络调用之前**本地过 `decode_hashedrekord_body` + `hashedrekord_verify_artifact_signature`（P-256 签 raw 32B digest，签名本身仍由维护者离线 openssl 经 `--signature-file` 提供，工具不签 P-256）；POST `/api/v1/log/entries`（`{"proposedEntry": ...}`，URL 默认取自 trust/policy.json 的 rekor 节，可用 `--rekor-url/--entries-path` 覆盖）；接受 200/201/409——409 幂等去重，优先信 `Location` 头解析既有 UUID 再 GET 回取；轮询 GET 直到出现 inclusionProof（兼容 verification 层与 legacy proof 层）；存储 body 的 digest/scheme 与本地提案逐一比对，漂移即 fail-closed；可选 `--rekor-pub` 在写出前用 `verify_hashedrekord_entry` 完整验 SET + RFC 6962 inclusion + checkpoint；产物原子写为入口对象（顶层 body/integratedTime/logID/logIndex/verification 五字段，**与引擎和录制 fixture 契约原样一致**）。支持 `--ca-file/--timeout/--poll-interval/--max-wait`，超时/HTTP 错误/非 JSON/缺字段全部 SigningError 不落盘；`--json` 输出 uuid/log_index/integrated_time/already_existed。
  - TR-9.1/9.2 测试 [tests/test_signing_tool.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_signing_tool.py) 新增 10 例（文件共 20 passed）：本地 `http.server.ThreadingHTTPServer` + 脚本化处理器（不打真实网络），合成 P-256 条目复用 test_rekor_verify 的 `p256_key/p256_sign_e/make_entry`（同 nonce 标签保证提案签名与日志条目一致）——① 成功提交即带 proof：断言 proposal 形状（Content-Type、apiVersion 0.0.1、kind、digest）、写出条目被 `trust.verify_hashedrekord_entry` 原样接受且 binding digest/scheme 与 manifest canonical digest 一致；② POST 无 proof 后轮询 3 次 GET 直到 inclusion；③ 409 + Location 去重回取（already_existed=True、GET URL 取 Location 中的真实 UUID 而非响应 map 的占位键、轮询 1 次）；④ HTTP 400 fail-closed 且不写文件；⑤ 201 非 JSON fail-closed；⑥ max_wait=0 无 proof 超时 fail-closed；⑦ 日志存储条目锚定不同 digest（digest drift）拒绝；⑧ 坏签名在本地 preflight 即拒（URL 指向不可达端口，证明网络前失败）；⑨ CLI `--json rekor-submit` 端到端 rc=0；⑩ TR-9.3 录制 fixture 的 binding（digest_hex/log_id/log_index）与 fixture_metadata.json 全一致、80 字符分片 UUID 与 source URL 吻合。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check scripts/keysmith_signing.py tests/test_signing_tool.py` 全过；`python3 -m py_compile codex-instruct.py scripts/*.py` 通过；全量 → **1353 passed, 25 skipped**（较 Task 8 基线 1343 净增 10），仅 2 个既有 `test_prompt_bank_regression.py` 缺 `OPENAI_BASE_URL` 失败（基线无关）。

## Task 10: verify_release.py 验证器与单文件合成
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 4, Task 5, Task 7
- **Description**:
  - 新增 `scripts/verify_release.py`：实现 FR-8 全顺序管线；参数：`--release-dir`、`--tag`、`--line stable|desktop-beta`、`--trust-dir`、`--root-file`、`--revocations-file`、`--allow-downgrade V [--reason]`、`--accept-revoked V --reason`、`--refresh-online`、`--rekor`、`--json`、离线/CI 模式。
  - root 引导三级优先 + TOFU 指纹显著输出；资产 sha256/size 流式核对 + SHA256SUMS 内容一致；manifest↔index 摘要；来源/构建器离线一致性与在线 tag 核对（git/HTTPS，仅显式在线时）；撤销/水位/override；Rekor 可选；通过后原子写 accepted 与审计。
  - 退出码契约（0 通过；10 签名/root；11 摘要；12 撤销；13 降级需 override；14 Rekor；15 状态损坏；1 其他）；人类可读 + `--json` 双输出；三平台路径安全。
  - 单文件合成：build_release 用既有 standalone 嵌入模式产出 `verify-release-v<tag>.py`（shebang+license+引擎+CLI，可独立运行/审计）。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-5, AC-6, AC-7, AC-8, AC-12, AC-14, AC-15
- **Test Requirements**:
  - `rule` TR-10.1: 资产篡改矩阵（每类资产翻转字节、SHA256SUMS 替换、manifest 字段篡改、多余/缺失文件）全部拒绝且退出码/错误层正确——证据：tests/test_verify_release.py
  - `rule` TR-10.2: 水位/override/撤销/root 轮换/TOFU/legacy 场景全分支（引用 Task 3/4 判定）在 CLI 层贯通——证据：同文件
  - `rule` TR-10.3: 离线默认零 socket（禁网夹具）；`--rekor` 用录制 fixture 通过；`--refresh-online` 用本地 mock 通过——证据：同文件
  - `rule` TR-10.4: 合成单文件可直接运行且 `--version`/`--json` 正常；在无源码仓库的临时目录独立工作——证据：同文件
  - `rule` TR-10.5: Windows/macOS/Linux 路径与权限行为（CI 矩阵）——证据：CI
  - `rubric` TR-10.6: 错误信息可行动性（失败层、资产名、期望/实际指纹、下一步建议）；scale 1-5；anchors 1=仅堆栈/模糊，3=主错误清晰但建议缺失，5=每条失败给出精确对象与修复动作；threshold >= 4；证据：输出快照评审
- **Completion Evidence**:
  - [scripts/verify_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/verify_release.py)（约 1300 行，纯标准库、Python 3.9、`from __future__ import annotations`；顶层零网络 import，由 AST 测试锁定）落地 FR-8 固定 11 步 fail-closed 管线：① 读+schema 校验 `release-manifest.json` 信封、`--tag/--line` 交叉核对 → ② root 解析/引导（`--root-file` → 在线 root.(N+1) → 发布目录 root.json → 固定副本；TOFU 自签 v1、轮换严格 +1 且必须满足旧 root threshold、同版本指纹不同静默替换拒、投喂旧版本 root 回滚拒、跳版本拒；TOFU 显著多行指纹+比对指引，root 过期仅警告）→ ②' `required_root_version` 闸与**时代 root 选择**（见引擎新增）→ ③ revocations（签名验证、同版本指纹幂等、更高版 `ensure_revocations_cumulative`、required 版本闸、过期只警告不失效）→ ④ manifest 角色签名/阈值（先验签，再剔除被撤 key 后重比阈值）→ ⑤ index 精确钉住 manifest hash/sequence（见引擎新增）→ ⑥ 资产（拒符号链接/子目录、多余/缺失文件拒绝、流式 sha256+size、SPDX-2.3/CycloneDX-1.6 结构校验、桌面 build-manifest digest+JSON、SHA256SUMS 严格解析且每行必须命中 manifest 且摘要一致；可选白名单 root/revocations/unsigned manifest/rekor-entry）→ ⑦ 资产/SBOM digest 与版本三类撤销判定 → ⑧ `evaluate_acceptance` 水位/精确版本 override/安全例外组合 → ⑨ 仅 `--refresh-online` 时 `git ls-remote` 核对注释 tag object 与 peeled commit、http(s) repo 形状校验 → ⑩ 仅 `--rekor` 时 `verify_hashedrekord_entry`（body digest==manifest canonical payload、scheme 必须 `ecdsa-p256-sha256`、root 中 derived logID+keyid 双匹配、index logIndex 一致）并单调记录 tree size → ⑪ 全过才原子写缓存 root/revocations/index + root 版本历史 + state + append-only audit + root-tofu/root-rotated/revocations-updated 事件；任何失败绝不推进水位。退出码 0/10/11/12/13/14/15/1 与层名双输出（人类 `REJECTED at the X layer` + 精确对象/期望实际/下一步；`--json` 稳定字段）；`--reason` 误用 1/13/12；`--version` 不要求 release-dir。在线辅助（https_fetch 404→OnlineNotFound、git_ls_remote 双 SHA 解析）与 urllib/subprocess 全部函数内懒导入。
  - 引擎 [scripts/keysmith_trust.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/keysmith_trust.py) 配合新增两块纯判定/IO 原语：(a) `ensure_index_extends(new, old)`——index 版本必须严格前进且旧条目逐位置逐字段保留（version bump 造假/丢历史/改历史拒）；(b) **root 版本链** `root_history_path/write_root_history/read_root_history`（信任目录不可变归档 `root.v<N>.json`，0700/0600 原子写）：轮换后旧 release 用 manifest `required_root_version` 指向的**留存时代 root** 验签（AC-5「旧签名持续可验」），而投喂旧 root 仍硬拒；旧发布目录携带的旧版 index 用时代 root 认证、但钉榜一律用已固定的最新 append-only index（不回滚 pin）。
  - TR-10.1～10.4 测试 [tests/test_verify_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_verify_release.py) **26 passed**（完整签名典礼工厂 tmp 目录造 release：4 core+SHA256SUMS+verifier+双 SBOM+root/revocations/manifest/index/可选 rekor-entry，合成 Rekor 条目复用 test_rekor_verify 辅助）：TOFU 持久化+root-tofu 审计+指纹警告；8 类篡改矩阵（core 字节/SHA256SUMS 追加/manifest 字段/index 字段/SBOM 翻转/缺文件/多余文件/符号链接）全拒且不产生 state.json；SBOM 形状错（hash 仍命中）拒；SHA256SUMS 内部不一致（外层 digest 重绑重签重建 index 后仍被内容交叉检查拒）；桌面 build-manifest 绑定与篡改；upgrade/reinstall 水位；downgrade 全分支（无参拒、错误版本 token 拒、精确版本+reason 放行且审计 from/to/manifest_hash/reason/UTC 时间）；被撤版本普通降级旁路无效、精确 `--accept-revoked`+reason 放行且活动安全例外持久化不重复、无 exception_allowed 死拒；被撤签名 key（阈值后重算）；被撤资产/SBOM digest；过期撤销仍生效/空命中仅警告；root 轮换 v1→v2（旧 threshold 签名）新旧 release 均通、投喂旧 root 回滚拒、缺旧阈值签名的自签 v2 拒、required_root_version 闸；**轮换后经留存 root.v1 历史验证 rel1 旧 release（无 root feed，签名/index/资产全通仅水位拦，override 放行+时代 root 警告；删除历史 fail-closed）**；index 替换检测（不同 signed 内容同版本→DIGEST 层）；tag/line 交叉核对；`--refresh-online` 注入 fetch/git 假函数（零真实网络）核对远端 tag、坏 tag 拒；Rekor 合成条目离线验证+tree size=7 水位写入、更小 tree 拒；`--rekor` 无 entry 以 EXIT_REKOR 拒；默认路径 monkeypatch socket 零联网；顶层 AST 无 urllib/socket/http/ssl/subprocess；build_release 合成单文件后子进程（隔离 cwd、精简 PATH/HOME）跑 `--version`（含 embedded 标记）与 `--json` TOFU；CLI JSON 成功/失败字段；`--reason` 误用退出码链（含真实 0.7.0→0.7.1→回滚链）。
  - TR-10.4 额外在**系统 Python 3.9.6**（/usr/bin/python3）手工冒烟：合成 standalone（202,231 字节）`--version` 正常；自造完整签名 release 目录 `--json` TOFU rc=0（root 分组指纹、rekor skipped 警告齐全）；篡改资产人类输出 `REJECTED at the artifacts layer` + 文件名+期望/实际字节数，rc=11；override 缺 reason rc=13。另确认 `/tmp` 符号链接祖先被拒（FR-15 跨平台安全规则，真实路径 /private/tmp 通过）。
  - TR-10.5（Windows/macOS/Linux CI 矩阵）与 TR-10.6（rubric 人工评审≥4）：代码仅用 pathlib/os.scandir 等跨平台原语且复用引擎既有符号链接祖先/权限规则，平台矩阵留待 Task 14 CI；本轮人工快照评审错误消息均含失败层+精确对象+期望/实际+下一步动作（如 root 回滚消息指引 retained history、缺时代 root 指引 --root-file/--refresh-online 逐级轮换）。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check codex-instruct.py tests scripts` 全过；`python3 -m py_compile codex-instruct.py scripts/*.py` 通过；全量 → **1379 passed, 25 skipped**（较 Task 9 基线 1353 净增 26），仅 2 个既有 `test_prompt_bank_regression.py` 缺 `OPENAI_BASE_URL` 失败（基线无关）。

## Task 11: 桌面 beta manifest 与打包接入
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 7, Task 10
- **Description**:
  - package_desktop_prerelease.py 增加显式 trust 产物开关：desktop-beta 未签名 manifest（FR-4 桌面集：DMG、两 candidate zip、NSIS、桌面 SHA256SUMS、两平台 build-manifest.json、桌面双 SBOM、verify-release 单文件），builder 段绑定两平台 build-manifest digest 与工具链；既有默认产物集合不变。
  - validate_desktop_candidate.py 暴露/校验 manifest 所需字段一致性（source commit、triple、版本）。
  - 验证器以 `--line desktop-beta` 复用同一管线。
- **Acceptance Criteria Addressed**: AC-1, AC-2, AC-9, AC-11
- **Test Requirements**:
  - `rule` TR-11.1: 开关关时既有桌面测试零回归；开时 manifest 覆盖全部桌面资产且 digest 可重算——证据：tests/test_desktop_trust.py（扩展现有 test_desktop_prerelease/candidate）
  - `rule` TR-11.2: 任一 build-manifest 被改/资产替换/缺 SBOM 时验证器拒绝——证据：同文件
  - `rule` TR-11.3: 桌面线 sequence/水位与 stable 线相互独立——证据：同文件
- **Completion Evidence**:
  - 一致性入口 [scripts/validate_desktop_candidate.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/validate_desktop_candidate.py)：新增纯函数（零文件/网络 IO）`manifest_identity(manifest)` 与常量 `BUILD_MANIFEST_TOOLCHAIN_FIELDS=(node,python,pyinstaller,rust)`，强校验 build-manifest 的 desktop/cli 版本（复用模块内 `_semver` 严格 X.Y.Z）、source commit（40 小写 hex）、target 必须恰为 macos/arm64/aarch64-apple-darwin/dmg/unsigned 或 windows/x86_64/x86_64-pc-windows-msvc/nsis/unsigned、toolchain 四字段非空字符串，返回规范化 identity dict（用 `dict(...)` 构造并加注释，规避 [tests/test_bump_version.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_bump_version.py) 对「字面量版本文件映射」的全模块扫描误伤）；失败一律 `CandidateError`。
  - 打包接入 [scripts/package_desktop_prerelease.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/package_desktop_prerelease.py)：顶部 import 守卫兼容「脚本直跑」与 `from scripts import` 两种方式；新增常量（`TRUST_UNSIGNED_MANIFEST_NAME=release-manifest.unsigned.json`、`LOCAL_SOURCE_REPO=local`、`DESKTOP_TAG_PREFIX=desktop-v`、两平台逻辑名 `build-manifest-macos.json`/`build-manifest-windows.json`、toolchain→builder 字段映射）；懒加载 `_trust_stack()`（build_release/generate_sbom/keysmith_trust/verify_release，顶层零新增重依赖）。`assemble_prerelease` 前 5 个位置参数不变、新增 keyword-only 开关组（`emit_trust_artifacts=False` 默认关、`trust_sequence/trust_issued_at/builder_info/source_repo/tag_object/repo_root/required_root_version/required_revocations_version`），关时给任何 trust-only 参数即报「trust-only options require emit_trust_artifacts=True」——**默认路径产出与文件集完全不变**。开关开时：参数校验（sequence≥1、ISO8601、builder_info dict、root≥1/revocations≥0、tag_object 40hex 或经 `_resolve_annotated_tag_object` 解析 git 注释 tag）→ 经典 5 产物先在 staging 内过 `verify_public_assets` → `_emit_desktop_trust_artifacts`：从 staging 的 candidate zip 直读 `build-manifest.json` 成员（断言与候选目录字节相同）写为两逻辑名（0644）、sha256 入绑定；两平台 `manifest_identity` 交叉一致（版本==VERSION、commit、unsigned target、toolchain 跨平台必须一致）；`_build_desktop_builder` 复用 `build_release._normalise_builder_info`，候选 build-manifest 是工具链权威记录，builder_info 只可同意不可冲突（python 默认从候选回填），`builder.build_manifests` 绑定两 digest；经 `build_release._verifier_standalone_bytes` 合成 `verify-release-<tag>.py`（0755）；`generate_sbom.build_documents(release_line=desktop-beta, include_desktop=True, fixed_files=(), extra_files=4 payload+SHA256SUMS+verifier+2 逻辑名)` 出 SPDX-2.3/CycloneDX-1.6 双 SBOM；manifest 的 artifacts 恰为 4 public payload+SHA256SUMS+verifier、sboms 恰 2，过 `trust.validate_release_manifest` 后写 unsigned manifest。rename 后 `verify_trust_prerelease` 全量重算（schema/line/commit/tag↔version；经典 5 产物+SHA256SUMS 精确覆盖+两 candidate zip 复核；逐 artifacts/sboms 重算 sha256/size 且 SBOM 过 `_check_sbom_document`；build-manifest 恰两逻辑名、磁盘 digest、与 zip 成员字节一致、identity/toolchain 一致；verifier 必须 `#!` 开头且不含 `VERIFIER_ENGINE_MARKER`；最终文件集精确 = artifacts∪sboms∪build_manifests∪{unsigned manifest}）。CLI：`assemble` 加 `--emit-trust-artifacts/--trust-sequence/--trust-issued-at/--source-repo/--tag-object/--required-root-version/--required-revocations-version`，builder info 经 `CODEX_KEYSMITH_BUILDER_INFO`、source repo 经 `CODEX_KEYSMITH_SOURCE_REPO`（常量与 build_release 逐字一致，有测试锁定）；`verify` 加 `--trust` 走 `verify_trust_prerelease`。验证器复用：desktop-beta 签名后直接走 Task 10 的 [scripts/verify_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/verify_release.py) 同一 11 步管线（`expected_line=desktop-beta`、tag `desktop-v<ver>-beta.N`），零分叉。
  - TR-11.1/11.2/11.3 测试 [tests/test_desktop_trust.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_desktop_trust.py) **15 passed**（importlib 复用 test_desktop_prerelease 的 `_candidate` 造完整两平台候选、test_verify_release 的签名典礼 `_seed/_root_envelope/_valid_spdx/_valid_cdx`，真实 REPO_ROOT 出真 SBOM，tag_object 直传绕过 git）：**TR-11.1** 开关关文件集精确==`PUBLIC_ASSET_NAMES`（5 个）且 trust-only 参数守卫；开关开文件集精确 11 个（4 payload+SHA256SUMS+verifier+双 SBOM+两逻辑 build-manifest+unsigned manifest），unsigned manifest 过引擎 schema 校验、line/tag/version/sequence/source/builder 字段与工具链绑定全部断言，逐 artifacts/sboms/build-manifest 从磁盘重算 sha256/size 全命中，`verify_trust_prerelease` 后置验证通过；两次 assemble 全 11 文件**字节级可复现**；CLI assemble/`verify --trust` 成功、经典 verify 对 trust 目录拒、缺 builder env 确定性失败；`manifest_identity` 三负例（坏 commit/坏 triple/空 toolchain）。**TR-11.2** 完整签名典礼（seal manifest/index + root.json）后 `verify_release` TOFU rc=0；篡改 build-manifest 字节→EXIT_DIGEST(11)/`build-manifests` 层；替换 DMG→`artifacts` 层；删 SPDX SBOM→缺文件 `artifacts` 层；重建 candidate zip 改 bundle 字节→EXIT_DIGEST；builder_info 工具链冲突与跨平台 toolchain drift 在打包期拒绝。**TR-11.3** 同一信任目录：desktop-beta beta.1(seq1) TOFU → 自造 stable 0.7.0(seq1) 接同一全局 index（version 2）TOFU → desktop-beta beta.2(seq2) 只推进桌面线为 upgrade；state 两线 accepted 的 version/sequence 各自独立；stable 旧 index 副本经已固定 append-only 榜 reinstall 通过且水位不动；桌面回滚 beta.1 以 EXIT_DOWNGRADE(13)/`downgrade` 拒而 stable 水位不变。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check scripts/package_desktop_prerelease.py scripts/validate_desktop_candidate.py scripts/build_release.py tests/test_desktop_trust.py` 全过（过程中修两处 I001）；`python3 -m py_compile codex-instruct.py scripts/*.py` 通过；定向 `tests/test_desktop_trust.py tests/test_desktop_prerelease.py tests/test_desktop_candidate.py tests/test_verify_release.py` → 100 passed；全量 → **1394 passed, 25 skipped**（较 Task 10 基线 1379 净增 15），仅 2 个既有 `test_prompt_bank_regression.py` 缺 `OPENAI_BASE_URL` 失败（基线无关）。期间发现并修复一处本次引入的全量回归：`manifest_identity` 返回字面量被 test_bump_version 版本文件扫描器误判，改 `dict(...)` 构造后该测试恢复通过。

## Task 12: codex-instruct.py 本地信任集成
- **Status**: `completed`
- **Priority**: medium
- **Depends On**: Task 4
- **Description**:
  - 新增 `--trust-status`：只读解析信任目录（root 指纹/版本、两线 accepted、revocations 版本/到期、活动例外、审计尾部），无信任时给出 onboarding 指引。
  - standalone 自洽：文件名匹配 `codex-instruct-v<X>.py` 且有 accepted 记录时，对 `__file__` 流式 sha256 与记录核对；不一致则部署类命令（`--yes`/reactivate 等写操作）fail-closed；源码树与无状态仅信息提示。
  - legacy onboarding：检测旧部署清单存在且无信任状态时，经显式确认记录 `legacy-onboarding` 审计；不阻断既有功能。
  - 仅用 hashlib/json/pathlib，不引入加密代码与任何网络 import。
- **Acceptance Criteria Addressed**: AC-12, AC-13
- **Test Requirements**:
  - `rule` TR-12.1: `--trust-status` 字段完整且与状态文件一致；畸形状态 fail-closed 提示——证据：tests/test_cli_trust.py
  - `rule` TR-12.2: 篡改 standalone 后写操作被拒、只读命令与源码树不受影响——证据：同文件
  - `rule` TR-12.3: legacy onboarding 一次性、写审计、可重复检测不重复记账——证据：同文件
  - `rule` TR-12.4: codex-instruct.py 无 urllib/socket/http 新增 import（ast 审计）——证据：同文件
  - `rule` TR-12.5: 既有 codex-instruct 测试零回归，coverage 不低于 81%——证据：CI
- **Completion Evidence**:
  - 引擎新增 accepted manifest 缓存 [scripts/keysmith_trust.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/keysmith_trust.py)（L1948-1994）：`accepted_manifest_path(trust_dir, manifest_hash)`（`manifests/<64hex>.json`，`require_hex(...,32)`，常量 `MANIFESTS_DIRNAME`）、`write_accepted_manifest`（load_envelope 校验 + `_type==RELEASE_TYPE` + ensure_trust_layout + 0600 原子写）、`read_accepted_manifest`（缺→None；`_type` 错或 canonical hash 与文件名不符抛 `MetadataError`）。验证器 [scripts/verify_release.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/verify_release.py)（L1148-1151）在 save_state 之后、append_audit_line 之前持久化 accepted manifest，TOFU/override 接受发布时绑定文件同时落缓存。
  - 本地信任集成段 [codex-instruct.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/codex-instruct.py) L17159-17905（marker 注释 `release-trust integration (FR-20)`，VERSION 保持 0.6.0 不动）：自包含、仅 hashlib/json/pathlib/os/re/datetime；常量全 `TRUST_` 前缀，`class TrustStatusError(RuntimeError)`。能力三块——① 只读状态：严格 state schema（顶层恰 schema_version/lines、两线恰 accepted/rekor_tree_size/security_exceptions、accepted 四字段+sequence≥1+64hex、例外唯一对）、root/revocations 缓存解析（signed/_type/version/到期）、audit.jsonl 逐行 JSON 事件校验，任一损坏聚合到 `read_trust_status` 的 `*_error` 字段（不抛散）；② standalone 自校验 `standalone_self_verification`：`classify_running_form`（source-tree/standalone/other，文件名正则 `^codex-instruct-v(\d+\.\d+\.\d+(?:-...)?)\.py$`），verdict 七态——not-applicable/no-trust-record/no-record-for-version 仅信息，state-error/record-unavailable/envelope-invalid/hash-mismatch `blocked=True`；仅核 stable 线、资产名 `codex-instruct-v{ver}.py`、流式 sha256+size 双比对，`main()` 在 `--yes/--restore-hooks` 部署类写操作前 gate，blocked 打印双语人类消息（含期望/实际 sha256）并 `sys.exit(1)`；③ 一次性 legacy onboarding：best-effort 读旧部署清单 tool_version（坏 JSON/非对象/空版本忽略）、semver 小于当前 VERSION 且跨目录去重，`legacy_onboarding_plan` 四态（signed-already/already-onboarded/none-found/needed），`perform_legacy_onboarding` 每旧版本一条审计（time/event=legacy-onboarding/line=stable/legacy_version/to_version/source=`--trust-onboard-legacy`，与引擎 `legacy_onboarding_audit_entry` 同构，canonical sort_keys+换行），信任目录 0700、audit 0600、`O_APPEND|O_NOFOLLOW`，非目录/符号链接信任路径抛错；幂等不重复记账。CLI 接线：`--trust-status`（只读，与写操作/onboarding 互斥 parser.error rc=2；任一 `*_error` rc=1）、`--trust-onboard-legacy`（单独运行总按结果 exit；与其他操作组合时仅失败才 exit、成功则继续原操作），中英文 epilog 各加两行示例；`CODEX_KEYSMITH_TRUST_DIR` 覆盖默认 `~/.codex-keysmith/trust`。
  - 测试 [tests/test_cli_trust.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_cli_trust.py) **71 passed**（importlib 以 `codex_instruct_cli_trust` 加载 hyphen 单文件；自带完整签名典礼 `_build_stable_release`：stable v0.7.0、root1/rel1、core 资产 `codex-instruct-v0.7.0.py`、双 SBOM，verify_release 真跑 TOFU）。TR-12.1：accepted 状态/root 指纹/revocations/audit 对账、空/缺目录信息提示、畸形 state/audit fail-closed、子进程 `--trust-status`；TR-12.2：verified/hash-mismatch（断言期望/实际 sha256+size）/record-unavailable/envelope-invalid（含 release_line/version/artifacts/record/sha256/size 六变体，重算 canonical hash 重定向 state 精确触发各守卫）/state-error/source-tree/无 state/no-record-for-version，子进程篡改 standalone `--reactivate --yes` rc=1 且消息含 sha256、只读 `--trust-status` 不受影响，进程内 monkeypatch gate 验证 sys.exit(1)；TR-12.3：needed→onboarded 整条字段+0600/0700 权限、already-onboarded 幂等、signed-already 不追加、同/新版本 none-found、多目录去重、信任路径非文件拒（rc=1）、CLI 两次仅一条、与 `--status` 组合成功后 fallthrough 不 exit；TR-12.4：AST 审计——整文件禁 urllib/http/socket/ssl/requests/cryptography/nacl/ftplib/smtplib，信任段 marker→main 间所有 FunctionDef/ClassDef 内零 import 节点；TR-12.5：15 例畸形 state 矩阵（非 UTF-8/非对象/顶层字段/schema/line/accepted/sequence bool/hex/空时间戳/tree_size/exceptions 五变体/重复例外/不可读文件）、root 与 revocations 缓存各 4/3 损坏变体、过期水位 EXPIRED 输出、安全例外/root/revocations/audit 全打印分支、进程内 main 四条接线（冲突 rc2/正常 rc0/写 gate rc1/onboarding+status fallthrough），无无断言用例。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check codex-instruct.py scripts/keysmith_trust.py scripts/verify_release.py tests/test_cli_trust.py` 全过（py38、line-length 100、E4/E7/E9/F/I/B）；`python3 -m py_compile codex-instruct.py scripts/*.py` 通过；全量 → **1465 passed, 25 skipped**（较 Task 11 基线 1394 净增 71），仅 2 个既有 `test_prompt_bank_regression.py` 缺 `OPENAI_BASE_URL/CODEX_KEYSMITH_AUTH` 失败（基线无关）。
  - TR-12.5 覆盖率：CI 等价命令（branch 覆盖，include=`codex-instruct.py,scripts/run_prompt_bank_regression.py`，fail-under=81）实测 **11637/14310 = 81.32%（TOTAL 81%，exit=0）**，其中 codex-instruct.py 单文件 81%（补测前 80.36%/80%）。本地复现注意：QC venv 的 coverage 装在用户 site 且缺 `.pth` 启动钩子，裸跑不追踪子进程；已在 `/private/tmp/cov-bootstrap/sitecustomize.py` 建等价引导，复现命令为 `COVERAGE_PROCESS_START="$PWD/pyproject.toml" PYTHONPATH="/private/tmp/cov-bootstrap" /tmp/keysmith-qc/bin/python -m coverage run --branch --parallel-mode -m pytest ...` 后 `coverage combine && coverage report`（跑完 `coverage erase`，数据文件不入库）。

## Task 13: stable 发布工作流 draft 签名门与 finalize 工作流
- **Status**: `completed`
- **Priority**: high
- **Depends On**: Task 8, Task 10
- **Description**:
  - release.yml 改造（tag ≥ policy.first_signed_version 分支）：构建开关产出未签名 manifest/SBOM/验证器；Release 以 draft 创建、上传全部资产（含 unsigned manifest）后停止，不 PATCH 公开；tag 更小走原路径（逻辑分支清晰，现有校验全保留）。
  - 新增 `.github/workflows/release-finalize.yml`：main-only workflow_dispatch（输入 tag、expected commit/tag object 等沿用恢复仪式风格）；从 draft 拉取维护者上传的 `release-manifest.json`、`release-index.json`、`rekor-entry.json`（维护者本地 gh upload 到 draft，密钥不离线机器）；调用 verify_release.py CI 模式独立复核（root 取自 main `trust/root/`、资产 digest、index、revocations、远端 tag、Rekor inclusion）；通过后把签名物料提交到 main `trust/releases/`（额外不可变渠道）并 PATCH draft=false；失败保持 draft。
  - 无签名物料/任一核验失败：禁止公开（分支测试通过脚本化可测部分；YAML 用钉版 action）。
- **Acceptance Criteria Addressed**: AC-10, AC-11, AC-14
- **Test Requirements**:
  - `rule` TR-13.1: 可脚本化的分支判定（tag 与 first_signed_version 比较、物料齐全性、finalize 前置检查）抽到 Python 辅助并单测三分支——证据：tests/test_release_publish.py
  - `rule` TR-13.2: YAML 中 publish 路径仅 finalize 工作流包含 `draft=false`；release.yml 新分支不含公开动作（静态检查 YAML 文本）——证据：同文件
  - `rule` TR-13.3: finalize 失败演练（坏签名/缺物料/坏 Rekor）工作流命令在夹具目录本地非零退出——证据：同文件
- **Completion Evidence**:
  - 新增纯标准库发布门辅助 [scripts/release_publish.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/scripts/release_publish.py)（argparse/json/os/re/subprocess/sys/tempfile/pathlib/typing，零第三方依赖，`if __package__ in (None,"")` 双导入守卫，全部 except→raise 带 `from exc`）。门规则：`parse_release_tag`/`signed_line_required`（`first_signed_version=null`→全走旧路；core<阈值 False；core==阈值但带 prerelease False；desktop tag 报错）、`validate_dispatch_refs`（tag object 与 commit 均 40 小写 hex 且不得相同）；物料前置 `missing_signed_materials`/`preflight_materials`（三件套必须存在且为 JSON object）；authority 选择 `read_required_versions`+`select_authority_files`（required root era 必须精确存在、revocations 累计取最新）；独立复核 `build_verifier_command`（`sys.executable -m scripts.verify_release`，cwd=仓库根，root 直传 main checkout 的精确 root.N、revocations 可选、`--rekor --json`）与 `run_independent_verifier`（非 0 抛 `VerificationRejected` 并透传验证器退出码，stdout 必须 JSON 且 ok is true）；不可变落库 `stage_signed_materials`（per-release manifest/rekor 已存在即拒、0644 原子写，channel index 原地推进）与 `enforce_channel_advances`（root 验签 + 对 main 已提交副本调 `trust.ensure_index_extends`，拒绝回放/分叉/丢历史，错误统一包装为 "does not extend the committed channel index"）；`run_finalize` 编排 parse↔line 一致→preflight→authority→独立验证器→渠道扩展校验→stage，返回 ok/tag/line/version/sequence/manifest_hash/root_version/revocations_version/staged。CLI 子命令 gate/check-refs/check-materials/next-sequence/authority-versions/finalize（--json）。
  - [.github/workflows/release.yml](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/.github/workflows/release.yml#L200-L734) 改造：L200-217 新增 `id: gate` 步骤（`release_publish.py gate --policy trust/policy.json`，case 严格校验输出恰为 true/false）；双构建步骤按 gate 条件注入 trust_flags（next-sequence/authority-versions 从 main 读数、root<1 即拒、`CODEX_KEYSMITH_BUILDER_INFO` 含 workflow_name/ref/workflow_sha/runner/python 版本，bash 数组空展开兼容 3.8/4.4），复现校验保留 legacy 原样（`diff -u` SHA256SUMS + 清单内 cmp 循环 + `sha256sum --check`），签名线额外 find 全文件 cmp 覆盖 SHA256SUMS 不含的双 SBOM/verifier/unsigned manifest；原发布步骤改名 `(legacy unsigned line)` 加 `if: signed == 'false'`，内容一字未动（draft=false、assets==5、WINDOWS marker、容错 PATCH 全保留）；L551-734 `BEGIN/END SIGNED-DRAFT-BRANCH (FR-21)` 包裹的签名线步骤（`if: signed == 'true'`）：独立复核远端 main/annotated tag、失败 trap 删除自建 draft、拒绝覆盖既有 Release、`draft=true` 创建并 find -maxdepth 1 上传全部产物、断言 draft is True 且资产集合恰为构建目录（含 unsigned manifest 与 verifier）、digest/size 对账、git clean、notice 指引维护者离线签名三件套并从 main 触发 release-finalize；块内绝无 draft=false/make_latest/-X PATCH/releases/latest。
  - 新增 [.github/workflows/release-finalize.yml](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/.github/workflows/release-finalize.yml)：仅 workflow_dispatch（release_tag/expected_tag_object/expected_commit），无 push/schedule，permissions contents: write，单 job；bind 步骤强校验 event/GITHUB_REF=main/WORKFLOW_SHA/远端 main HEAD/非 shallow + check-refs；独立核验远端 annotated tag（verification.verified=true、reason=valid、peeled commit）；下载 draft 前断言 draft is True、资产名防路径穿越、check-materials；`release_publish.py finalize`（root/revocations 只从 main checkout 读，YAML 不含 --root-file/--revocations-file）；提交前再次复核远端 main 未推进且 tag 未变，`git add trust/releases` 且变更只能在该前缀（grep -v 守卫）、无变更即失败；发布前最后复核 tag 与四件套（三件套+unsigned），全文 `-F draft=false` 恰 1 次，PATCH 后轮询 latest 并终态断言 draft False/prerelease False/published_at/四件套/latest_tag==tag；无 .key.json/secrets./-X DELETE。action 全部钉版 SHA（checkout # v7、setup-python # v6），YAML 解析与全部 run 块 `bash -n` 通过。
  - 测试 [tests/test_release_publish.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_release_publish.py) **35 passed**。TR-13.1（纯函数/CLI 三分支单测）：null 阈值与阈值矩阵 7 例（v0.6.0 False、v0.7.0-rc1 False、v0.7.0 True 等）、坏 tag/desktop tag、check-refs（40hex 与互异）、物料缺失/非 JSON/preflight、required versions、authority 选择矩阵（root 缺/版本 0/revocations 取最新）+ authority-versions CLI、next_sequence（缺文件=1/递增/desktop=1/坏 JSON/坏 line/真实空 channel=1）、verifier 命令形状、staging 三目标+0644+拒覆盖、channel advances（首发放行、第二发布扩展、回放拒、篡改签名拒）。TR-13.2（YAML 静态断言 8 个）：gate/分支条件/构建开关在场；签名块四禁项（draft=false、make_latest、-X PATCH、/releases/latest）且 legacy 块外旧发布行为全保留；release.yml 与 finalize yml 仅钉版 action（本地 reusable workflow `./` 引用豁免）；finalize main-only dispatch/无密钥无 DELETE；draft=false 全文恰 1 次、root 权威不来自 draft、物料前缀守卫、发布前三件套断言、tag 复核 ≥2 处；辅助脚本 AST 无网络导入。TR-13.3（夹具目录子进程演练，复用 test_verify_release 签名典礼工厂，root.1 跨发布共享同一 main checkout 且断言字节一致）：成功 finalize（staged 路径、state accepted、manifest_hash）、第二发布扩展 channel；失败全部非零退出——缺 index rc1、坏 manifest 签名 rc=EXIT_SIGNATURE、篡改 core 资产 rc=EXIT_DIGEST、rekor logIndex+1 rc=EXIT_REKOR、缺 root.1 rc1、line/tag 不符 rc1、签名有效但重写已固定渠道历史的分叉索引 rc1（stderr 含 extend、v0.7.1 目录不得创建）、删 channel 后重跑撞 per-release 不可变 "already exists" rc1；另含 in-process run_finalize 纯路径用例。
  - 既有契约测试 [tests/test_release_artifacts.py](file:///Users/kkcarrot/swe-project/codex-keysmith_fork3/tests/test_release_artifacts.py) 同步更新 1 处计数：远端 main 独立复核由 2 处变 3 处（bind 仪式、legacy 发布、签名 draft 分支各一次），其余 legacy 断言（diff -u/SHA256SUMS cmp 循环/assets==5/DELETE/PATCH 容错等）全部保持通过。
  - 验证命令与结果：`/tmp/keysmith-qc/bin/ruff check scripts/release_publish.py tests/test_release_publish.py` 全过；`/usr/bin/python3 -m py_compile scripts/release_publish.py tests/test_release_publish.py` 通过；全量 → **1500 passed, 25 skipped, 2 deselected**（较 Task 12 基线 1465 净增 35），仅 4 个既有缺 `OPENAI_BASE_URL/CODEX_KEYSMITH_AUTH` 的 http 用例（test_codex_instruct.py 与 test_prompt_bank_regression.py 各 2）按基线 deselect，与本次改动无关。新脚本未纳入 pyproject coverage include（Task 15 统一扩展）。

## Task 14: 桌面 beta 发布签名门
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: Task 11, Task 13
- **Description**:
  - desktop-candidate.yml 的 publish-desktop-prerelease：签名线 beta tag（policy 门）在签名物料核验通过前保持 draft；新增/复用 finalize（desktop-finalize）执行 desktop-beta 验证器复核、Rekor 核验、签名物料入 `trust/releases/` 后公开；既有 signed annotated desktop tag/main HEAD/不可覆盖控制全部保留。
- **Acceptance Criteria Addressed**: AC-11
- **Test Requirements**:
  - `rule` TR-14.1: 物料缺失/桌面 manifest 与 candidate digest 不符/Rekor 失败 → 不公开（脚本化判定单测 + YAML 静态断言）——证据：tests/test_release_publish.py
  - `rule` TR-14.2: 现有 beta 发布控制（tag 核验、不可覆盖、latest 语义）不回归——证据：既有 workflow 文本核对 + 现有测试

## Task 15: CI 门禁扩展与 sigstore oracle
- **Status**: `pending`
- **Priority**: medium
- **Depends On**: Task 9, Task 10
- **Description**:
  - tests.yml：py_compile/ruff/coverage 纳入新模块（coverage include 列表扩展并维持 81%；run_scenario_bank 65% 门不变）；新增全部 trust 测试进三平台矩阵。
  - 新增 main/schedule 触发的 `rekor-oracle` job：pip 临时安装 sigstore-python，对录制 fixture UUID 从公共 Rekor 重取并验证，再与纯标准库验证器结论比对，必须一致（不阻塞 PR，失败发 warning/失败在 main 可见）。
  - 无网络证明纳入默认测试集（socket 禁用夹具）。
- **Acceptance Criteria Addressed**: AC-7, AC-8, AC-17
- **Test Requirements**:
  - `rule` TR-15.1: 新测试在 3.9/3.10/3.12/3.14 × 三平台通过——证据：CI 运行
  - `rule` TR-15.2: oracle 脚本对录制条目输出 "agreement=ok"；分歧即非零——证据：tests/oracle 辅助脚本 + CI
  - `rule` TR-15.3: ruff/coverage 门槛保持——证据：CI

## Task 16: 用户安装文档与代装指令
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 10
- **Description**:
  - README.md / README.en.md：安装流程改为多渠道获取 root 指纹 → 下载验证器单文件 → 验证（默认离线；可选 `--rekor` 在线透明日志）→ 再运行 CLI；保留旧 SHA256SUMS 作为补充；桌面 beta 同样指引。
  - docs/agent-install.md：中英代装文本改为强制执行验证器、报告指纹/水位/撤销状态，禁止绕过。
- **Acceptance Criteria Addressed**: AC-15, AC-16
- **Test Requirements**:
  - `rule` TR-16.1: 文档中所有命令与验证器实际参数/退出码一致（文档命令抽取干跑测试）——证据：tests 中文档命令一致性测试
  - `rule` TR-16.2: 不残留"仅 SHA256SUMS 即足够"表述；威胁模型边界（TOFU、不防用户运行已持有旧脚本）有明确说明——证据：文本断言

## Task 17: SECURITY.md / CODE_SIGNING_POLICY.md 信任模型与运维 runbook
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 13, Task 14
- **Description**:
  - SECURITY.md（中英双语段）：信任层级与威胁模型、root 指纹多渠道清单与核对方法、泄露分级与紧急撤销流程（多久内发布 revocations、用户 side-load 步骤、安全例外语义）、Rekor 锚定说明、隐私承诺（默认不联网）。
  - CODE_SIGNING_POLICY.md：签名线发布控制（draft→离线签名→finalize）、双离线密钥保管与轮换仪式、first_signed_version 启用步骤、与 Apple/Authenticode/SignPath 的关系（明确不是原生签名）、桌面 beta 签名门。
  - 保留 WINDOWS_FRESH_DEPLOYMENT_POLICY 标记机制（两份 README/SECURITY 等文件的标记一致性）。
- **Acceptance Criteria Addressed**: AC-15, AC-16
- **Test Requirements**:
  - `rule` TR-17.1: 既有政策标记测试继续通过；新增 runbook 步骤与工具子命令一一对应（命令存在性/参数一致性自动检查）——证据：测试
  - `rubric` TR-17.2: runbook 盲走质量（值班者仅凭文档可完成 keygen/root 仪式/轮换/紧急 revoke/finalize）；scale 1-5；anchors 1=关键步骤缺失，3=主线可走应急缺失，5=全流程可独立照做含排错；threshold >= 4；证据：评审记录

## Task 18: 全量质量收口
- **Status**: `pending`
- **Priority**: high
- **Depends On**: Task 12, Task 15, Task 16, Task 17
- **Description**:
  - 全量 pytest（三平台本地可达范围）、ruff、py_compile、coverage；端到端演练：构建（开关）→ fixture 签名 → Rekor mock/录制 → 验证 → 轮换 → 撤销 → 降级 override 的完整剧本脚本化留存（tests 内）。
  - 检查工作流 YAML 钉版、permissions 最小化（contents:read 默认，仅 finalize/publish job write）、无密钥流入 inputs/日志。
- **Acceptance Criteria Addressed**: AC-14, AC-17
- **Test Requirements**:
  - `rule` TR-18.1: 完整剧本一次跑通且每个负例节点 fail-closed——证据：tests/test_trust_e2e.py
  - `rule` TR-18.2: `ruff check`、全量 pytest、coverage 门槛、workflow 权限静态检查全部通过——证据：本地运行输出
  - `rubric` TR-18.3: 整体安全姿态评审（最小信任面、密钥不出 air-gap、可恢复性）；scale 1-5；threshold >= 4；证据：独立 Review
