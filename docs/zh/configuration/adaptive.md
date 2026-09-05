# 按目标自适应选择

`adaptive` 配置会在后台为频繁访问的目标学习更合适的节点。它不会在前台
连接路径中同步探测或计算评分。

## group 边界

每个 adaptive 条目必须引用一个同名的既有 outbound group。group 仍由
routing 决定；自适应逻辑只能从该 group 当前健康的成员中选择。`default`
的推荐绝不可能用于 `ai`，反之亦然。重试逻辑排除的节点也不会被强行选中。

## 建议上线方式

先使用 `shadow` 模式。dae 会按 group 统计嗅探到的 TCP
`域名:端口:IP 版本`，只保留有上限的一组热点目标，并通过该 group 内的
健康节点进行后台探测。443 端口执行带证书和 SNI 校验的 TLS 握手，其他
端口执行 TCP connect。shadow 会生成日志、推荐和指标，但不改变实际选择。

观察推荐、探测结果和前台连接错误率后，再逐个 group 改为 `enforce`。
推荐过期、节点不健康、节点不在当前 group 或被重试逻辑排除时，dae 会立即
退回该 group 原有的 policy。

```jsonc
global {
    metrics_listen: '192.168.1.106:2024'
    # 默认关闭，避免域名泄露和 Prometheus 高基数。
    metrics_target_labels: false
}

adaptive {
    default {
        mode: shadow
        max_targets: 64
        min_connections: 20
        observation_window: 10m
        idle_ttl: 1h
        probe_interval: 5m
        probe_timeout: 5s
        probe_ports: 443
        max_concurrent_probes: 4
        max_probes_per_minute: 60
        recommendation_ttl: 15m
        switch_tolerance: 50ms
        switch_min_percent: 20
    }

    ai {
        mode: shadow
    }
}
```

热点观察队列是非阻塞的；每个 group 的目标数、探测并发和探测速率都有
硬上限。健康节点之间切换时，新节点需要连续两次胜出，并同时超过绝对和
相对改善阈值；当前推荐不健康时则立即替换。

当前只学习带有已知嗅探域名、且端口列在 `probe_ports` 中的 TCP 目标（默认
只有 443）。IP-only、UDP 和其他端口继续使用原有 group policy。保留默认值
还可以避免向任意应用协议建立后台 TCP 连接。

## 指标

设置 `metrics_listen` 后，`/metrics` 会提供 group/node 健康状态、原有
policy 当前选择、前台拨号结果、自适应探测结果、跟踪目标数量和观察事件
丢弃数。只有显式启用 `metrics_target_labels` 才会导出精确目标标签。

该端点不提供认证，应只监听可信接口并通过防火墙限制访问。
