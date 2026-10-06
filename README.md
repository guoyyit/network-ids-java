# network-ids-java

本地网络入侵检测引擎。输入为模拟抓取的报文流（内存 `PacketPipe` 或直接喂 `List<Packet>`），
在传输层维护 TCP 连接状态、按序重组乱序/重复/重叠载荷，并在重组后的连续字节流上执行
固定内容特征匹配（支持跨包边界），命中产生可聚合、可去重、可崩溃恢复的告警。

不依赖任何外部服务或真实网卡；除 Spring Boot（沿用脚手架）外无额外运行期依赖。

## 快速开始

```java
IdsConfig config = new IdsConfig();
config.setStateDir("ids-state");

try (IdsEngine engine = new IdsEngine(config)) {
    engine.open();                        // 从上次提交点恢复
    engine.addRule(RuleParser.parse("EVIL: content:|65 76 69 6C|; message:evil string"));

    for (Packet p : packets) {
        ProcessResult r = engine.process(p);
        for (AggregatedAlert a : r.getAggregatedAlerts()) {
            // 处理聚合后告警
        }
    }
}
```

## 包结构

- `model`：报文 `Packet`、四元组 `FlowKey`、TCP 标志 `TcpFlags`、状态枚举、异常事件。
- `engine`：`StreamReassembler`（重组）、`TcpFlow`（连接状态机）、`FlowTable`（流表/回收）、
  `IdsEngine`（门面）。
- `detect`：`Rule`、`RuleParser`、`RuleSet`（COW 热更新）、`StreamScanner`（KMP 扫描）。
- `alert`：`Alert`、`AggregatedAlert`、`AlertAggregator`（窗口聚合）。
- `persist`：`CheckpointStore`（WAL 持久化与恢复）。
- `input`：`PacketPipe`（内存管道）。

## TCP 连接状态机

连接双方各维护一个独立的“发送端”状态机。一个报文同时表达“本方发送事件”和“对对端的确认”，
因此两个方向的状态都可能被同一个报文推进。

状态（`TcpState`）：

```
发起方:  CLOSED -> SYN_SENT -> (收 SYN/ACK) -> ESTABLISHED -> FIN_WAIT_1
                 -> FIN_WAIT_2 -> TIME_WAIT -> CLOSED
响应方:  LISTEN -> (发 SYN-ACK) SYN_RCVD -> (收 ACK) ESTABLISHED
                 -> CLOSE_WAIT -> LAST_ACK -> CLOSED
同时关闭: FIN_WAIT_1 -> CLOSING -> TIME_WAIT
```

非法/畸形报文分类（`AnomalyType`），均不会修改既有状态：

- `INVALID_FLAG_COMBINATION`：`SYN+FIN`、`SYN+RST` 或出现保留位。
- `ILLEGAL_STATE_TRANSITION`：当前状态下不允许的标志组合（如 ESTABLISHED 后再发裸 SYN）。
- `DATA_ON_NON_ESTABLISHED`：三次握手完成前到达数据。
- `DATA_AFTER_CLOSE`：RST 关闭后仍到达数据。
- `FLOW_TABLE_FULL`：流表达上限且无可回收连接。
- `BAD_SEQUENCE` / `MALFORMED_PACKET`：保留分类。

`RST` 无条件立即关闭两个方向并停止重组；后续报文被归类但不破坏状态。

### 连接重建（同四元组）

连接**终止**后，相同四元组可以立即重建。终止的判定（确定且只依赖当前状态机）：
两个方向都处于收尾态，即各自为 `CLOSED`、`FIN_WAIT_2` 或 `TIME_WAIT`
（RST 之后双向 `CLOSED`；四次挥手完成之后双向 `FIN_WAIT_2`）。
半关闭（一侧仍可发数据）与建连中途都不算终止。

终止后的连接上到达**裸 SYN**（`SYN` 置位且 `ACK` 不置位）时，引擎将其判定为
新连接的握手起点：状态机、两个方向的重组器与扫描器、ISN 归一化基准、
发起方标识全部清零，随后按全新连接处理——新握手与其后的数据报文
不会被判为非法，命中偏移按新 ISN 从 0 开始。

陈旧报文与新连接报文的区分是确定的：

- 只有裸 SYN 会触发重建重置；旧连接的重传（`SYN+ACK`、数据、`FIN` 等）不会。
- 旧连接的数据重传在新握手完成前到达：归类 `DATA_ON_NON_ESTABLISHED` 并丢弃。
- 旧连接的数据在新连接建立后到达：按新 ISN 归一化后落在已交付区间的
  被整体忽略（不产生重复命中），落在未来区间的仅缓存、不影响已交付内容。

见 `ConnectionRebuildTest`。

## 载荷重组与重叠规则

`StreamReassembler` 按绝对序列号维护 `TreeMap` 片段，从下一个空洞位置开始连续交付。

重叠规则是**确定且可复现的”序列号较小者优先（lowest-SEQ-wins）”**：同一字节被多个段覆盖时，
取覆盖它的、起始序列号最小的段内容。由此：

- 乱序：先缓存，空洞补齐后按序交付。
- 重复：起始/覆盖范围已交付的部分被整体忽略，不产生重复字节。
- 重叠：与报文严格按序到达的结果逐字节一致（见 `ReassemblyTest.overlapMatchesInOrderArrival`）。
- **同起点不同长度**：先缓存/已交付的内容保留，后到的段只贡献超出既有覆盖范围的尾部；
  完全被覆盖的后到段整体忽略。因此两种到达顺序与按序到达产出的字节序列完全一致
  （见 `ReassemblyTest.sameStart*` 与 `EngineDetectionTest.sameStartSegments*`）。

序列号以连接初始 ISN 归一化为从 0 开始的相对偏移。

## 规则语法

```
<ruleId>: [direction:<forward|reverse|both>;] content:<字符串 或 |十六进制|> [nocase;] [message:<说明>;]
```

- `content`：明文（如 `content:malware`）或 `|AA BB|` 形式的十六进制，二者可混用，如
  `content:GET |2F|`。十六进制允许无空格连续书写。
- `nocase`：大小写不敏感匹配。
- `direction`：`forward`（客户端→服务端）、`reverse`、`both`/省略为双向。
- `#` 开头为注释。

匹配在重组后的连续流上用 KMP 完成；扫描器为每条规则保留部分匹配状态，
因此特征跨越多个报文（甚至跨乱序重组边界）仍能命中。告警携带规则、连接、方向、
流内绝对偏移与命中文本上下文（前后若干字节，可打印字符直出，其余以 `\xHH` 表示）。

### 规则热更新

`RuleSet` 使用 copy-on-write 的不可变快照：检测线程无锁读当前快照，
`addOrUpdate/remove/replaceAll` 原子替换快照。正在使用旧快照的检测仍会完成，不中断检测、
不漏检。流内扫描器在同步时保留内容未变化规则的跨包匹配状态。规则快照随提交点持久化，
重启后恢复到最近提交时的规则集。

## 告警聚合与窗口边界

聚合键 = 规则 ID + 连接（规范化四元组）+ 方向。窗口是按**事件时间**（报文时间戳，非墙钟）
计算的左闭右开翻滚窗口：

```
windowStart = floor(ts / W) * W
窗口区间      = [windowStart, windowStart + W)
```

- 同一聚合键在一个窗口内的多次命中只产生一条 `AggregatedAlert`，
  含 `hitCount`、`firstHitMillis`、`lastHitMillis` 与首次命中上下文。
- **边界行为**：时间戳恰好等于 `windowStart+W` 的命中属于**新窗口**，并触发旧窗口刷出。
- 事件时间需单调不减；固定回放因此完全确定。

## 流表容量与老化回收

所有回收判定均基于报文事件时间（保证回放可复现，不依赖调度器/墙钟）。

- 老化（每个报文处理前 `tick`）：回收 TIME_WAIT 到期、僵死、超寿命、空闲连接。
- 容量满（`maxFlows`）时按优先级确定性腾位：已关闭 > TIME_WAIT 到期 > 最久空闲 > 僵死 >
  超寿命；同优先级取 `lastSeen` 最早，再按连接标识字典序兜底。
- 没有可回收连接时产生 `FLOW_TABLE_FULL` 异常并安全丢弃该报文，既有流状态不受影响。
- 流表与每条流分别加锁，并发检测与回收不会处理到已移除的流；`maxFlows` 与
  `maxReassemblyFragmentsPerFlow` 保证长期运行内存有界。

### 回收时的在途数据处理

连接被回收（容量驱逐或老化）前，其在途数据**先排空检测再释放**，不会静默丢弃：

- 每个方向缓存的重组片段按序列号序合并为最大连续段（段间空洞跳过、不补零），
  逐段以独立扫描器检测——已交付内容不会被重复扫描，跨越空洞也不会凭空制造命中。
- 排空产出的数据块随当前 `ProcessResult.getChunks()` 返回；命中进入与正常报文
  完全相同的管线（重放去重 → WAL 待提交 → 窗口聚合），告警时间戳/序号取
  回收发生处报文的事件时间，因此聚合窗口的事件时间单调性不被破坏，
  结果与逐条顺序处理一致（见 `EvictionFlushTest`）。
- 已命中并进入聚合器的结果属于引擎级状态，不随连接回收而丢失；
  未到期窗口在回收前后保持原有合并语义，不会产生重复或错分的聚合告警。

## 关闭语义

`IdsEngine.close()` 与 `process()` 互斥：正在处理的报文先完整处理完毕再执行关闭。
关闭时：

- 聚合器中**尚未到期窗口**的全部结果被刷出并留存，通过
  `drainClosedTailAlerts()` 以可观察方式取走（取出即清空），不会在关闭路径被静默丢弃。
- 执行一次最终提交（连续序号水位 + 待确认告警身份 + 规则快照）并关闭 WAL。
- 关闭是幂等的；关闭后再调用 `process()` 会抛出 `IllegalStateException`，
  调用方能明确感知而非结果被静默吞掉。

见 `CloseFlushTest`。

## 崩溃恢复与持久化

`CheckpointStore` 在状态目录维护单个预写日志 `ids.wal`，两类记录：

- `PENDING_ALERT`：命中后、上报前追加并 `fsync`，保证“已命中未提交”不丢。
- `COMMIT`：原子记录“已连续处理到的报文序号 + 已提交告警身份集合 + 规则快照”。

记录帧格式为 `MAGIC | 长度(int) | 体 | CRC32`。读取时长度或 CRC 不匹配即视为
**崩溃造成的截断尾部并丢弃**，单条记录永远不会被部分当成有效数据（无部分写入）。

- 重启后 `open()` 从最近 COMMIT 恢复位置与规则；重放时序号 `<= 提交水位` 的报文被跳过，
  因此不会重复检测/重复上报已提交告警（已提交身份集合再做一层去重）。
- 最后一次 COMMIT 之后仍为 PENDING 的告警通过 `recover().getPendingAlerts()` 提供补报，
  保证已命中结果不丢。
- 提交水位只在“已处理序号连续”时推进，乱序到达不会让高序号先提交而漏掉低序号。

## 可复现性

固定的报文序列 + 规则集，在任意运行次数下产出逐条一致的告警：老化与窗口均以事件时间驱动，
回收受害者选择有确定的并列裁决，扫描与重组均为确定性算法。见
`EngineDetectionTest.replayIsDeterministic`。

## 全部配置项（`IdsConfig`）

| 配置项 | 默认值 | 含义 |
| --- | --- | --- |
| `maxFlows` | 10000 | 流表最大连接数，超出触发确定性回收或 FLOW_TABLE_FULL |
| `idleTimeoutMillis` | 300000 | 空闲连接老化时间 |
| `zombieTimeoutMillis` | 600000 | 僵死（长期无进展且未正常关闭）老化时间 |
| `timeWaitMillis` | 120000 | TIME_WAIT 停留时间 |
| `maxFlowLifetimeMillis` | 3600000 | 单连接最大寿命 |
| `maxReassemblyFragmentsPerFlow` | 10000 | 每方向最多缓存的重组片段数（超出丢弃最远片段，内存有界） |
| `alertWindowMillis` | 60000 | 告警聚合翻滚窗口大小 |
| `commitEveryNPackets` | 100 | 每处理多少报文尝试提交一次（仅连续序号推进提交水位） |
| `maxCommittedRetain` | 100000 | 保留的已提交告警身份数量上限（用于重放去重） |
| `stateDir` | `ids-state` | WAL 与状态目录 |

## 测试

`mvn test`，覆盖：重组乱序/重叠/重复/同起点不同长度（两种到达顺序均断言完整内容）、
TCP 非法状态迁移、同四元组连接结束后重建（握手+数据+陈旧报文分类）、规则热更新、
告警聚合窗口与边界、流表容量与老化（含回收时在途数据排空与命中保留）、
正常关闭时的在途命中刷出、崩溃恢复（续传/补报/截断尾部）、
并发检测与回收、以及固定回放可复现。

关键验证入口：

- `ReassemblyTest` / `EngineDetectionTest`：重组一致性（含同起点段两种顺序的内容断言）。
- `ConnectionRebuildTest`：四次挥手/RST 后同四元组重建的完整握手与数据流程。
- `EvictionFlushTest`：容量驱逐与空闲/僵死老化下在途数据的排空、命中与聚合一致性。
- `CloseFlushTest`：关闭路径的尾部聚合刷出与并发在途命中守恒。
