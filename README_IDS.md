# 本地网络入侵检测引擎（network-ids-java）

一个完全运行在本地、无外部服务依赖的网络入侵检测引擎。输入为模拟抓取的 TCP 报文流（内存管道注入或固定列表回放），引擎完成：

1. TCP 连接全生命周期状态跟踪，畸形报文与非法状态迁移分类上报且不污染状态；
2. 乱序 / 重复 / 重叠报文的确定性流重组；
3. 有界流表 + 空闲/僵死老化回收，驱逐时先冲刷在途数据，内存占用有界；
4. 固定内容与跨包边界特征匹配（Aho-Corasick），规则运行中热增删；
5. 告警窗口聚合去重，携带命中次数与首次/末次命中时间；
6. CRC 保护的提交日志 + 原子快照 + 投递水位的崩溃恢复；
7. 固定输入下任意次数运行结果逐条一致（可复现回归）。

仅依赖 Spring Boot 已自带的 Jackson 与 JUnit 5，不连接真实网络、不依赖外部进程。

## 快速开始

```bash
mvn test          # 全部 48 项自动化测试
mvn spring-boot:run
```

启动后可通过本地 HTTP 接口操作（默认端口 8080）：

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| `POST` | `/ids/rules` | body 为单行规则文本，新增/替换规则 |
| `GET` | `/ids/rules` | 查看当前规则集 |
| `DELETE` | `/ids/rules/{id}` | 运行中删除规则 |
| `POST` | `/ids/packets` | 注入一个模拟报文（JSON） |
| `GET` | `/ids/status` | 活动流数、规则数、最近提交位置 |
| `GET` | `/ids/alerts` | 查看去重后的当前告警 |

注入报文示例：

```json
{"timestamp":3,"srcIp":"10.0.0.1","srcPort":1000,
 "dstIp":"10.0.0.2","dstPort":80,"seq":1001,"ack":0,
 "flags":"PA","payloadHex":"736563726574"}
```

`flags` 可传字母组合（`S/SR/SA/PA/FA/F/R/A/U/P`，大小写不敏感）或 `0x..`/十进制位掩码。报文 JSON 字段：`timestamp, srcIp, srcPort, dstIp, dstPort, seq, ack, flags, payloadHex`。

编程方式直接使用 `IdsEngine`：

```java
IdsConfig config = IdsConfig.defaults();
CheckpointStore store = new CheckpointStore("data/ids");
IdsEngine engine = new IdsEngine(config, store, alert -> { },
        RuleParser.parse("evil: hex|736563726574"));
for (Packet p : source.loadAll()) {
    engine.processPacket(p);   // 同步检测 + 原子提交
}
engine.close();
```

## TCP 连接状态机

方向由「第一个 SYN 的发送方」确定：该方向为 `INITIATOR`，对端为 `RESPONDER`。全局维护一个简化的 RFC 793 状态：

```
NEW
  └─ SYN(发起方) ───────────────► SYN_SENT
SYN_SENT
  ├─ SYN+ACK(响应方) ───────────► SYN_RCVD
  ├─ SYN(发起方, 重传) ──────────► SYN_SENT（保持）
  └─ RST ───────────────────────► CLOSED
SYN_RCVD
  ├─ ACK(发起方) ───────────────► ESTABLISHED
  └─ RST ───────────────────────► CLOSED
ESTABLISHED
  ├─ FIN(发起方) ───────────────► FIN_WAIT_1
  ├─ FIN(响应方) ───────────────► CLOSE_WAIT
  ├─ RST ───────────────────────► CLOSED
  └─ 数据 / ACK ────────────────► ESTABLISHED
FIN_WAIT_1
  ├─ ACK(响应方) ───────────────► FIN_WAIT_2
  ├─ FIN(响应方)+ACK ───────────► TIME_WAIT
  ├─ FIN(响应方, 同时关闭) ──────► CLOSING
  └─ RST ───────────────────────► CLOSED
FIN_WAIT_2 ──FIN(响应方)────────► TIME_WAIT ──RST──► CLOSED
CLOSE_WAIT ──FIN(发起方)────────► LAST_ACK
LAST_ACK   ──ACK(响应方)────────► CLOSED
CLOSING    ──ACK(响应方)────────► TIME_WAIT
CLOSED     ──SYN(发起方)────────► SYN_SENT（连接转世，incarnation+1）
任意状态   ──RST────────────────► CLOSED
```

### 畸形报文与非法迁移分类

异常以 `TcpAnomalyEvent(position, timestamp, flowKey, direction, type, detail)`
交给可选的 anomaly listener；异常报文被整体丢弃，**不会进入重组器**，因此既不会破坏引擎状态，也不会使后续检测错位。

| `TcpAnomalyType` | 触发条件 |
| --- | --- |
| `NULL_SCAN` | 所有标志位为 0 |
| `MALFORMED_FLAG_COMBINATION` | SYN+RST、SYN+FIN、RST+FIN 等非法组合 |
| `DATA_ON_SYN` | SYN 报文携带非空载荷 |
| `DATA_WITHOUT_CONNECTION` | 连接未建立 / 半连接阶段出现数据 |
| `ACK_WITHOUT_CONNECTION` | 未建立连接时出现孤立 ACK |
| `SYN_IN_ESTABLISHED_STATE` | ESTABLISHED/TIME_WAIT 后再次出现 SYN |
| `INVALID_STATE_TRANSITION` | 其它不被当前状态允许的迁移 |
| `REASSEMBLY_LIMIT_EXCEEDED` | 乱序缓存超过每方向容量，该新段被整体拒绝 |

端口越界（非 1..65535）在 HTTP 入口直接返回 400。

## 流重组与重叠规则

每个连接的每个方向各有一个 `StreamReassembler`，在看到对应方向的 SYN（发起方 SYN / 响应方 SYN+ACK）时用其 ISN 锚定首字节序号。支持 32 位序号回绕。

- **乱序**：不连续的段进入有序缓存；缺口被填补后按序产出连续字节块。
- **重复**：完全被覆盖的旧字节不重复计入。
- **重叠（确定且可复现）**：冲突字节一律由「起始序号最小」的段胜出；起始序号相同时，由「捕获位置（position）更小」的段胜出。该规则与报文到达顺序无关，因此同一批报文无论顺序/重复/重叠如何到达，重组出的字节流完全一致。
- **容量**：每方向 `ids.max-buffered-bytes-per-direction` 为上限；一个新乱序段若会使缓存超限则被**整体原子拒绝**（不做部分接受，行为简单可预测），并产生 `REASSEMBLY_LIMIT_EXCEEDED`。已连续可交付的字节不计入乱序缓存。

## 检测规则语法

每行一条规则，`#` 开头为注释（也支持行尾 `#` 注释）：

```text
# 规则 id : 内容
rule1: 41 42 43                 # 等价于 hex|414243，匹配 "ABC"
rule2: hex|deadbeef
rule3: ascii|GET /admin
```

- `hex|....`（或直接写十六进制）：十六进制字节，允许空格分组，必须为偶数位；
- `ascii|....`：UTF-8 字面内容；
- 规则 id 非空，同一规则集内 id 唯一，重复 id 抛 `RuleParseException`。

匹配器为有状态 Aho-Corasick：自动机状态在 chunk 之间保持，模式跨包边界仍精确命中一次；重叠模式全部上报；命中携带流内绝对偏移与上下文（命中点两侧各 `ids.context-radius` 字节，上下文可跨 chunk）。

### 规则热更新语义

规则集采用 copy-on-write 不可变快照：检测中途增删规则永远不会打断进行中的一次检测，也不会漏检「已在该规则生效范围内」的命中。

- **删除**：立即生效，其它规则的跨包匹配状态连续保留。
- **新增**：新规则只对其生效**之后结束**的命中告警；规则加入之前已经结束的历史内容不追溯。为保证既有规则跨包连续性，匹配器保留 `max(最长规则长度-1, context-radius)` 字节的回看。

## 告警聚合与窗口边界

目标身份为「连接 5 元组 + 连接转世 incarnation」，聚合键为
`(connectionId, ruleId, direction)`。

- 窗口为**翻滚窗口**，半开区间 `[first, first+windowMs)`：
  - 第一次命中立即产生 1 条告警（`hitCount=1`）；
  - 窗口内后续命中**不新增告警**，而是在同一确定性 `alertId` 上就地更新
    `hitCount`、`lastTimestamp`（upsert 语义，按 alertId 幂等）；
  - 命中时刻 **恰好等于** `first + windowMs` 时，旧窗口关闭、新窗口开启，产生一条新的 `alertId`。
- 每条告警包含：`alertId, connectionId, ruleId, firstTimestamp, lastTimestamp, hitCount, direction, firstOffset, contextHex`。
- 首次命中上下文随该聚合告警输出。

## 流表容量与老化

- 容量：`ids.max-flows`。表满时新连接到来前确定性驱逐「最久未见（LRU）」的流；驱逐回调先冲刷该流两个方向所有已重组数据与打开的聚合窗口，因此**不会丢失在途命中**。
- 老化依据报文时间戳（非墙钟）：
  - 任意流空闲超过 `idle-timeout-ms` 回收；
  - `CLOSED/TIME_WAIT` 的僵死连接按更短的 `closed-timeout-ms` 回收。
- 有界性：流数有上限；每方向乱序缓存有上限；规则与匹配器按活动流/方向惰性创建、随驱逐销毁。长期运行内存有界。
- 所有检测在引擎单锁内串行完成；规则快照为无锁读，因此老化、注入、规则热更新并发时状态一致。

## 崩溃恢复

持久化目录包含三类文件：

- `commit.log`：定长帧提交日志，帧格式
  `magic(4) | length(4) | JSON payload | CRC32(4)`，每条提交 `fsync` 后才返回。
  打开时顺序扫描，遇到截断、长度非法或 CRC 不匹配的**撕裂尾部**即截断丢弃，单条记录不可能部分生效。
- `snapshot.json`：先写临时文件、fsync、原子 rename，故快照要么完整存在要么不存在。快照包含规则集、所有活动流的 TCP 状态、两端 ISN/已消费序号、未交付乱序段和匹配器前缀状态，恢复后可精确继续（包括崩溃前已到达但缺口未补齐的乱序段命中）。
- `delivery.pos`：投递水位（原子 rename 写入），记录已成功外发告警的最高提交位置。

恢复流程：

1. 载入最新快照（规则、全部流、匹配器前缀），回放位置定为快照位置；
2. 读取快照之后的提交记录，跳过 `position <= delivery.pos` 的记录（恰好一次，不重复上报）；
3. 对快照之后、尚未确认投递的记录补投告警（崩溃若发生在「已提交、未外发」窗口，不丢失已命中结果），补投成功后推进水位；
4. 此后从「最近已提交位置」继续检测。

「不重复上报」针对已确认投递的提交；「不丢失」针对已提交但未确认投递的提交——两者由 commit 记录 + 投递水位共同保证。单条提交记录把位置与其告警作为一个原子单元，不会出现部分写入。

## 可复现性

- 所有检测判定（老化、窗口、告警时间戳）只使用报文自带 `timestamp` 与全局 `position`，绝不读取墙钟或随机源。
- `alertId` 由 `(connectionId, ruleId, direction, firstTimestamp)` 确定性派生。
- 固定 `PacketSource`（相同报文序列）+ 相同规则集在任意运行次数下产出逐条一致的告警（见 `EngineIntegrationTest#fixedReplayIsReproducibleAcrossRuns`、`CrashRecoveryTest#repeatedRunsProduceIdenticalAlertSequence`）。
- 报文来源：`ListPacketSource`（固定回放）与 `InMemoryPacketPipe`（本地内存管道，同步注入并保留全部报文以便续测）。

## 全部可配置项

| 属性 / `IdsConfig` 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `ids.max-flows` / `maxFlows` | 10000 | 流表容量上限 |
| `ids.idle-timeout-ms` / `idleTimeoutMs` | 600000 | 空闲流老化时间（ms） |
| `ids.closed-timeout-ms` / `closedTimeoutMs` | 30000 | 终态流老化时间（ms） |
| `ids.max-buffered-bytes-per-direction` | 1048576 | 每方向乱序缓存字节上限 |
| `ids.aggregation-window-ms` / `aggregationWindowMs` | 60000 | 告警聚合窗口（ms），半开 |
| `ids.context-radius` / `contextRadius` | 32 | 命中上下文两侧保留字节数 |
| `ids.snapshot-interval` / `snapshotInterval` | 1024 | 每 N 个已提交报文落一次快照 |
| `ids.checkpoint-dir` / `checkpointDir` | `data/ids` | 提交日志/快照/水位目录 |
| `ids.persistence-enabled` / `persistenceEnabled` | true | 是否启用持久化与恢复 |

## 包结构

- `ids.model`：报文、5 元组、TCP 标志位；
- `ids.tcp`：状态枚举、方向、异常类型/事件、TCP 状态机；
- `ids.reassembly`：流重组器与重组块；
- `ids.flow`：单连接状态与有界流表；
- `ids.rule` / `ids.detect`：规则模型/解析/热更新集合与 Aho-Corasick 匹配器；
- `ids.alert`：告警模型、聚合器、sink；
- `ids.persistence`：提交日志、快照、投递水位；
- `ids.source`：内存/回放报文源；
- `ids.engine`：`IdsConfig` 与编排门面 `IdsEngine`；
- `config` / `web`：Spring 装配与本地 HTTP 接口。

## 测试覆盖

| 测试类 | 覆盖 |
| --- | --- |
| `TcpStateMachineTest` | 握手/正常挥手/被动关闭/RST/畸形报文/非法迁移 |
| `StreamReassemblerTest` | 乱序、重复、重叠确定性、同起点规则、缓冲上限、序号回绕 |
| `StreamingMatcherTest` | 固定匹配、跨包边界、重叠模式、重复命中、上下文、热更新预热 |
| `RuleAndAggregatorTest` | 规则解析/重复 id、规则集增删、窗口聚合、边界、目标区分 |
| `FlowTableTest` | 空闲老化、终态快老化、容量 LRU 驱逐、touch 保活 |
| `EngineIntegrationTest` | 端到端命中、乱序一致性、畸形报文不串位、规则热增删、聚合、容量驱逐、可复现回放 |
| `ConcurrencyTest` | 检测与规则热更新并发 |
| `CheckpointStoreTest` | 提交读写、撕裂尾部/CRC、原子快照 |
| `CrashRecoveryTest` | 崩溃补投恰好一次、快照后不重复、乱序在途命中跨崩溃、可复现 |
| `IdsControllerTest` | HTTP 注入/规则增删/状态 |
