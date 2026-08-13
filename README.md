
---

# cfprobe

Cloudflare CDN / 反向代理 识别引擎。通过综合 **IP 段归属、DNS 解析、TLS 握手、HTTP 指纹** 四路证据，
以 **基于规则的证据评分引擎** 判定一个 `IP + Hostname` 是否是 Cloudflare 边缘节点上的站点，
并给出置信度、详细证据链和各阶段探测结果。

## 特性

- **多路证据融合**：Cloudflare 官方 IP 段 + DNS 多解析器共识 + CNAME 链 + TLS 证书 + HTTP 头指纹（`CF-Ray`、`Server: cloudflare` 等）
- **可插拔策略**：内置 `CloudflareWebProxyV1` 策略；也可实现 `DetectionPolicy` trait 自定义分类规则
- **安全 SSRF 防护**：`TargetPolicy` 默认拒绝私网 / link-local / 组播 / localhost 等目标，可按需放宽
- **多级缓存**：
  - DNS 内存缓存（TTL + 容量淘汰）
  - Cloudflare 官方 IP 范围：内存 + 磁盘 + 跨进程文件锁 + stale-while-revalidate
- **高并发**：
  - 单目标内 DNS / TLS / HTTP 三路探测并发执行
  - DNS 单解析器内 A/AAAA、MX、TXT、NS 并发；多解析器同时并发
  - 批量扫描：可控并发度 + RPS 限流 + 按目标超时 + CancellationToken 取消
- **运行模式**：
  - Rust 库（`cfprobe` crate）
  - 命令行（`cfprobe probe / scan / serve`）
  - HTTP 服务（`axum`，`/probe` 单目标 + `/scan` 批量 + `/metrics` 统计）
- **完整观测**：每个阶段有独立 `ProbeResult`，含 `duration`、错误、最终 `DetectionResult`（总分、置信度等级、正负证据列表、可读 summary）

## 架构

```
                        ┌──────────────────────────────────┐
                        │          CfProbe (facade)        │
                        └──────────────────────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          │                          │                          │
    ┌─────▼─────┐              ┌─────▼─────┐              ┌─────▼─────┐
    │  IP/DNS   │              │    TLS    │              │   HTTP    │
    │ Detector  │              │  Prober   │              │  Prober   │
    └─────┬─────┘              └─────┬─────┘              └─────┬─────┘
          │                          │                          │
          └──────────────────────────┼──────────────────────────┘
                                     ▼
                        ┌──────────────────────────┐
                        │     Evidence Engine      │
                        │  + DetectionPolicy       │
                        └──────────────────────────┘
                                     │
                                     ▼
                      DetectionResult {
                        classification, confidence,
                        score, evidence[], summary
                      }
```

阶段顺序：
1. `CloudflareRanges` — 加载官方 IP/CIDR（内存 cache → 磁盘 cache → HTTP）
2. `Ip` — 本地 CIDR 匹配，判断 IP 是否归属 Cloudflare
3. `Dns` / `Tls` / `Http` — **三路 join 并发**
4. `Evidence` — 汇总所有信号，按策略打分分类

## 快速开始

### 作为库使用

Cargo.toml:

```toml
[dependencies]
cfprobe = "0.1"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

#### 单次探测

```rust,no_run
use std::net::IpAddr;
use cfprobe::{CfProbe, CfProbeConfig, Target};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 构建长期存活的探测器（内部会初始化 DNS/HTTP/TLS 客户端和缓存）
    let config = CfProbeConfig::cloudflare_web_proxy_v1()?;
    let probe = CfProbe::new(config).await?;

    // 2. 定义目标（IP + SNI/Host 主机名 + 端口 + scheme）
    let target = Target::https("104.16.77.250".parse::<IpAddr>()?, "example.com");

    // 3. 执行探测
    let result = probe.detect(target).await?;

    println!("is_cloudflare   : {}", result.is_cloudflare());
    println!("classification  : {:?}", result.detection.classification);
    println!("confidence      : {:.2}", result.detection.confidence);
    println!("confidence_level: {:?}", result.detection.confidence_level);
    println!("score           : {}",   result.detection.score);
    println!("summary         : {}",   result.detection.summary);

    Ok(())
}
```

#### 批量扫描（流式）

```rust,no_run
use std::net::IpAddr;
use std::time::Duration;
use futures::StreamExt;
use cfprobe::{BatchScanConfig, CfProbe, CfProbeConfig, Target};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let probe = CfProbe::new(CfProbeConfig::cloudflare_web_proxy_v1()?).await?;

    let targets = vec![
        Target::https("104.16.77.250".parse::<IpAddr>()?, "example.com"),
        Target::https("104.16.76.250".parse::<IpAddr>()?, "example.org"),
    ];

    let config = BatchScanConfig::default()
        .with_concurrency(32)                   // 最多同时探测 32 个目标
        .with_requests_per_second(Some(50))     // 限流 50 QPS
        .with_target_timeout(Duration::from_secs(30)); // 单目标超时 30s

    // scan_unordered 按完成顺序返回，不是输入顺序
    let mut stream = probe.scan_unordered(targets, config)?;
    while let Some(item) = stream.next().await {
        match item.status {
            BatchItemStatus::Ok(result)  => println!("{:?} → {:?}", item.target.ip, result.detection.classification),
            BatchItemStatus::Timeout     => println!("{:?} timed out",   item.target.ip),
            BatchItemStatus::Cancelled   => println!("{:?} cancelled",   item.target.ip),
            BatchItemStatus::Error(err)  => println!("{:?} err: {}",     item.target.ip, err),
        }
    }
    Ok(())
}
```

### 命令行

```sh
# 构建
cargo build --release

# 单次探测
./target/release/cfprobe probe --ip 104.16.77.250 --hostname example.com

# 批量扫描（从 targets.jsonl 读取，每行一个 JSON Target）
./target/release/cfprobe scan \
    --input targets.jsonl \
    --output results.jsonl \
    --concurrency 32 \
    --requests-per-second 50 \
    --target-timeout-secs 30

# 启动 HTTP API 服务
./target/release/cfprobe serve --listen 127.0.0.1:8080

# JSON 结构化日志
./target/release/cfprobe --json-logs probe --ip ...
```

### HTTP API

启动服务：`cfprobe serve --listen 0.0.0.0:8080`

#### `GET /version`

```json
{ "name": "cfprobe", "version": "0.1.0" }
```

#### `POST /probe` 单目标

```sh
curl -X POST http://127.0.0.1:8080/probe \
  -H 'Content-Type: application/json' \
  -d '{
    "ip": "104.16.77.250",
    "hostname": "example.com",
    "port": 443,
    "scheme": "https"
  }'
```

返回完整的 `ProbeResult`（含 IP/DNS/TLS/HTTP/Evidence 各阶段详情、错误列表）。

#### `POST /scan` 批量

```sh
curl -X POST http://127.0.0.1:8080/scan \
  -H 'Content-Type: application/json' \
  -d '{
    "targets": [
      {"ip": "104.16.77.250", "hostname": "example.com", "port": 443, "scheme": "https"},
      {"ip": "104.16.76.250", "hostname": "example.org", "port": 443, "scheme": "https"}
    ],
    "concurrency": 16,
    "requests_per_second": 20,
    "target_timeout_secs": 30
  }'
```

按完成顺序 streaming 返回 `application/x-ndjson`（每行一个 `BatchItemResult`）。

#### `GET /metrics`

纯 JSON 指标（请求总数、成功/失败/超时/取消计数、Cloudflare 三态分类计数、in_flight 等）。

## 核心概念

### Target（探测目标）

```rust
pub struct Target {
    pub ip:       IpAddr,    // 直连 IP
    pub hostname: String,    // SNI + Host 头 + DNS 查询名
    pub port:     u16,
    pub scheme:   HttpScheme, // Http / Https
}
```

便捷构造：
- `Target::https(ip, hostname)` → port=443 + Https
- `Target::http(ip, hostname)`  → port=80  + Http

### DetectionClassification（最终分类）

| 枚举值 | 含义 |
|---|---|
| `Cloudflare`     | 综合证据判定为 Cloudflare 代理 |
| `NotCloudflare`  | 综合证据判定不是 Cloudflare |
| `Unknown`        | 证据不足，或 Cloudflare 官方 IP 段加载失败且 `require_cloudflare_ranges = true` |

### ConfidenceLevel（置信度等级）

`VeryHigh > High > Medium > Low > Insufficient`

置信度由 `DetectionPolicy::ConfidenceRuleSet` 的 `(base + score/divisor)` 公式计算，
并按阈值映射到等级。

### EvidenceItem（证据条目）

每个 `EvidenceItem` 包含：
- `kind`: `EvidenceKind` 枚举（共 22 种，如 `CloudflareIpRange`、`HttpCfRay`、`DnsResolverConsensus`…）
- `direction`: `Positive` / `Negative` / `Neutral`
- `category`: `Ip` / `Dns` / `Tls` / `Http`
- `score`: 该条证据的加权分（正值加分、负值减分，最终累加到 `DetectionResult.score`）
- `detail`: `serde_json::Value` 可读细节

最终 `summary` 字段会把所有证据按正负数量、强信号拼成人可读的一句话说明。

## 模块速览

- **`cloudflare`** — 官方 IP 段拉取（`CloudflareClient`）+ 多级缓存（`CloudflareRangeCache`：内存 / 磁盘 fs2 文件锁 / stale fallback）+ 命中检测
- **`dns`** — 抽象 `DnsBackend` + `HickoryDnsResolver` (hickory-resolver, 支持 DoH) + `DnsPool`（多解析器并发聚合，可插拔 DNS 内存缓存）+ `DnsDetector`（CNAME 链遍历、多解析器共识、私网应答过滤、熔断、PTR 反查）
- **`tls`** — rustls 握手，证书 SHA256 / subject / issuer / SAN 解析；支持 `verify_certificate` 与 `observation_fallback`（验证失败但仍记录证书信号）
- **`http`** — reqwest 连接池复用（按 `(scheme, ip, hostname, port)` 缓存 Client），抽取 Cloudflare 头信号（CF-Ray / CF-Cache-Status / Server: cloudflare / CF-Connecting-IP 等）
- **`evidence`** — `EvidenceEngine` + `DetectionPolicy`；内置 `CloudflareWebProxyV1` 是一组针对 Cloudflare Web 反代的调优规则集（IP 段 25 分、DNS 共识、CNAME 指向 Cloudflare、CF-Ray 头 50 分等）
- **`probe`** — 外层 facade：`CfProbe`、`CfProbeConfig`、`TargetPolicy`（SSRF 防护）、批量 `scan_unordered`
- **`server`** — axum HTTP 服务：`/probe` `/scan` `/metrics` `/health` `/version`，JSON metrics

## 性能要点

本引擎设计用于**批量扫描公网目标**，核心性能关键路径：

| 优化点 | 实现 |
|---|---|
| DNS 多路并发 | 解析器间并发（semaphore 控制） + 单解析器内 A/AAAA/MX/TXT/NS `join!` 并发 |
| 单目标三阶段并发 | DNS / TLS / HTTP `tokio::join!`，总耗时 ≈ max(三阶段) 而非 sum |
| TLS ClientConfig 预构建 | `TlsProber::new` 时一次性初始化 RootCertStore（webpki-roots 150+ 根），缓存 `Arc<ClientConfig>` |
| HTTP 连接池 | 按目标 (scheme, ip, hostname, port) 复用 `reqwest::Client`，避免每次重建 connector |
| 平滑 RPS 限流 | `StartRateLimiter` 预约式槽位：先短暂持锁排期、再解锁 sleep，避免持锁等待阻塞其他任务 |
| Cloudflare 缓存 | 三级 cache：内存 `RwLock` → 磁盘 JSON（`fs2` 文件锁跨进程互斥） → stale-while-revalidate（网络失败时可回退陈旧磁盘缓存）|
| DNS 内存缓存 | 容量上限 + TTL 双重淘汰；CNAME 链、IP、MX、TXT、NS、PTR 六类独立缓存 |
| 批量取消 | `CancellationToken` 贯穿所有阶段：IP 范围拉取、DNS、TLS、HTTP、PTR、证据引擎全路径可提前退出 |

## SSRF / 目标策略

`TargetPolicy::cloudflare_web_proxy_v1()` 默认启用以下防护（可调）：

- ❌ 拒绝 loopback / RFC1918 / link-local / 组播 / unspecified / documentation(192.0.2.x 等) / benchmark / IPv4 映射 IPv6 的私网段
- ❌ 拒绝 hostname 为 `localhost` / `.local.` / `.internal.` / `.localhost`
- ❌ 拒绝 DNS 解析结果为私网 IP（可避免 DNS rebinding）
- ❌ 仅允许 Cloudflare Web Proxy 官方端口：
  - HTTP: 80, 8080, 8880, 2052, 2082, 2086, 2095
  - HTTPS: 443, 2053, 2083, 2087, 2096, 8443

可单独构造 `TargetPolicy` 并通过 `CfProbeConfig::with_target_policy()` 覆盖以适配内网扫描场景。

## 安全说明

1. `cfprobe` 是**主动出站探测**工具，目标 IP/端口完全由调用方提供。请在接入不可信输入前过一层 `TargetPolicy::validate_target / validate_dns`。
2. rustls 采用 `ring` 加密提供者，首次使用前请在 main 入口调用 `cfprobe::init_rustls_crypto()`（在 `CfProbe::new` 内部会自动调用；如果直接使用单独模块如 `TlsProber::new` 请手动调用一次）。
3. HTTP 探测最大 body 读取量由 `HttpProbeConfig.max_body_bytes` 控制（默认 1 MiB），避免大响应吞带宽。
4. 批量扫描的 QPS、并发度、超时请按出口带宽和对端容忍度合理设定；`CloudflareWebProxyV1` 仅用于授权资产审计。

## 测试

```sh
# 单元/集成测试（排除需要真实公网访问的 slow tests）
cargo test

# 单独跑集成测试（需要真实公网访问）
cargo test --test probe -- test_probe_one_way --include-ignored --nocapture
```

## License

MIT