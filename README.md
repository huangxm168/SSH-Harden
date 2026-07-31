# ssh-harden

一条命令完成 SSH 公钥安装、端口修改、防火墙放行与密码登录禁用。**全程自我校验，任何环节失败自动回滚**，专门针对「远程改 SSH 配置把自己关在门外」这个问题设计。

面向 **Debian 12 / 13**。Ubuntu 24.04 也已通过全部测试，但不是主要目标（详见[兼容性说明](#兼容性说明)）。

## 为什么需要它

远程加固 SSH 最大的风险不是配置写错，而是**写错了却毫不知情**——命令返回成功，服务也重启了，直到断开连接才发现再也连不回去。

一个真实案例。在某商家的 Debian 12 VPS 上执行加固操作后，22 端口的密码和新端口的密钥**同时失效**，只能通过 VNC 控制台救援。事后查明，该商家的镜像出厂就在 `sshd_config` 末尾预置了：

```
PasswordAuthentication yes
PubkeyAuthentication no      ← 密钥认证被商家关闭了
```

于是当加固操作关闭密码认证时：

| 认证方式 | 状态 | 谁关的 |
| --- | --- | --- |
| 密码认证 | ❌ 关闭 | 本次加固操作 |
| 密钥认证 | ❌ 关闭 | 商家镜像预置 |
| 键盘交互 | ❌ 关闭 | Debian 12 默认 |

三条路同时断掉，sshd 可用认证方式变为**空集**。公钥其实已经正确写进了 `authorized_keys`，只是 sshd 被配置成压根不看它。

这种状态有个很直观的判别方法——看 SSH 拒绝时括号里的内容：

```
Permission denied ()                      ← 空集，已锁死
Permission denied (publickey,password)    ← 正常
```

`ssh-harden` 的核心目标就是让这类情况**不可能发生**：禁用密码前必须先自证密钥确实可用，且任何一步出错都会自动回到执行前的状态。

## 快速开始

```bash
# 安装公钥 + 改端口 + 自动放行防火墙（保留密码登录，最安全）
bash <(curl -fsSL https://raw.githubusercontent.com/huangxm168/SSH-Harden/main/ssh-harden.sh) \
  -g <GitHub用户名> -p 54278

# 先预演，看清所有改动后再实际执行
bash <(curl -fsSL https://raw.githubusercontent.com/huangxm168/SSH-Harden/main/ssh-harden.sh) \
  -g <GitHub用户名> -p 54278 -d --dry-run

# 出问题一键还原
bash <(curl -fsSL https://raw.githubusercontent.com/huangxm168/SSH-Harden/main/ssh-harden.sh) --rollback
```

**推荐的操作顺序**（这样绝不会锁死）：

1. 先只装密钥、改端口，**不加 `-d`**
2. 另开一个终端，用密钥登录新端口，确认成功
3. 再执行 `-d` 禁用密码登录

脚本会在第 3 步自动检测你当前会话是不是密钥登录的——如果是，说明密钥链路已验证，可以放心禁用密码。

## 选项

**密钥来源**（可重复、可组合）

| 选项 | 说明 |
| --- | --- |
| `-g, --github <用户名>` | 从 `https://github.com/<用户名>.keys` 获取 |
| `-u, --url <URL>` | 从指定 URL 获取 |
| `-f, --file <路径>` | 从本地文件读取 |
| `-s, --stdin` | 从标准输入读取 |

**配置**

| 选项 | 说明 |
| --- | --- |
| `-p, --port <端口>` | 修改 SSH 端口 |
| `-d, --disable-password` | 禁用密码登录（执行前强制校验密钥可用） |
| `-o, --overwrite` | 覆盖模式，清空原有 `authorized_keys` |
| `--user <用户名>` | 目标用户，默认 root |
| `--no-firewall` | 不自动放行防火墙 |

**安全与调试**

| 选项 | 说明 |
| --- | --- |
| `-n, --dry-run` | 预演，打印所有改动但不执行 |
| `-y, --yes` | 跳过交互确认（自动化用） |
| `--force` | 跳过「当前会话是否密钥登录」的确认（危险） |
| `--rollback` | 从最近备份还原并重启服务 |

短选项兼容 `getopts` 的传统写法，组合与粘连均可：`-ou <URL>` 等价于 `-o -u <URL>`，`-p54278` 等价于 `-p 54278`。

## 安全设计

### 一、禁用密码前的三重证据

`-d` 不是简单地把 `PasswordAuthentication` 改成 `no`，而是先要求同时满足：

1. **`sshd -T` 确认 `PubkeyAuthentication` 已生效为 `yes`** —— 直接挡住上述锁死场景
2. **`authorized_keys` 逐行校验** —— 文件存在、含至少一个合法公钥、权限 ≤ 600、目录权限 ≤ 700
3. **当前会话是否即为密钥登录** —— 从 auth 日志比对 `$SSH_CONNECTION` 的客户端端口

第 3 条是最硬的证据：如果你当前就是用密钥连进来的，那禁用密码必然安全。若当前是密码登录，脚本会明确警告并要求确认。

同时，只要指定了 `-d`，脚本会**自动把 `PubkeyAuthentication` 设为 `yes`**，从根源上消除「关了密码却没有密钥可用」的可能。

### 二、事务化改动

```
备份 → 修改 → sshd -t 语法校验 → 重启 → sshd -T 核对生效值
                ↓ 任一步失败
            自动回滚到备份并重启恢复
```

被安全护栏拒绝的场景也会回滚。否则半成品配置留在磁盘上，当时不会断连，但**下次 sshd 重启就会按残留配置启动**，等于埋下定时炸弹。

### 三、以生效值为准，而非配置文件

sshd 的配置优先级相当微妙：`Include` 指令的位置、drop-in 文件的字母序、首值优先规则，都会影响最终结果。与其猜测，不如直接问 sshd。

脚本写完 drop-in 后一律用 `sshd -T` 验证；若发现未生效（说明 `Include` 位置靠后或不存在），自动回退到修改主配置文件。

### 四、默认保守

密钥默认追加而非覆盖；覆盖需显式 `-o` 并二次确认；`--dry-run` 可完整预演所有改动。

### 五、把话说清楚再问

需要你拍板的地方只有几处，但每一处都是高危操作，所以提示一律给全四件事：**当前是什么情况**、
**选 y 会怎样**、**选 n 会怎样**、**想满足条件该怎么做**。默认值写在明面上——直接回车等于取消并
回滚，不靠 `[y/N]` 里那个大写字母暗示。输入接受 `y`/`yes`/`n`/`no`，敲错了会重新问而不是一错就
中止。动手之前还会先打印一份执行计划，让你知道接下来会发生什么。

## 实现要点

几个容易出问题、本项目专门处理了的地方：

- **公钥内容逐行校验**：用 `ssh-keygen -l` 验证，URL 返回错误页或 HTML 时直接拒绝，不会把垃圾写进 `authorized_keys`
- **不做模糊的 sed 替换**：配置精确写入 drop-in 文件。像 `s@.*\(Port \).*@...@` 这类正则会命中所有含关键字的行，包括注释和无关配置
- **识别 socket 激活**：Ubuntu 22.10+ 默认由 `ssh.socket` 监听端口，此时改 `sshd_config` 的 `Port` 完全无效，端口写入 socket 单元；即使 `ssh.socket` 当前没在监听、只是处于 enabled，也会一并写入——否则改端口当场看着成功，一重启就被 socket 抢回旧值
- **socket 模式下的重启顺序**：必须先停 `ssh.service` 再重启 `ssh.socket`。顺序反了 systemd 会拒绝（`Socket service ssh.service already active, refusing`），新端口根本不会生效
- **服务名自适应**：Debian 是 `ssh.service`，其他发行版可能是 `sshd.service`
- **防火墙自动放行**：识别 ufw / firewalld 并放行新端口。工具不存在或使用 nftables / iptables 时明确警告，而不是静默失败
- **参数顺序无关**：先解析全部参数，再按固定顺序执行（装密钥 → 改端口 → 放行防火墙 → 禁密码）
- **取值等价判断**：`PermitRootLogin prohibit-password` 会被 `sshd -T` 报告为 `without-password`，两者等价，校验时做归一化处理

## 关于配置写入位置

改动默认写入 `/etc/ssh/sshd_config.d/10-ssh-harden.conf`，不污染主配置文件。

序号取 `10` 是为了排在 `50-cloud-init.conf` 等常见 drop-in 之前——sshd 采用**首值优先**，先读到的配置生效。

在 Debian 12 与 13 上，`Include /etc/ssh/sshd_config.d/*.conf` 均位于主配置**第 12 行**（文件开头），因此 drop-in 天然压过主文件后面的所有设置。前述案例中商家写在第 122 行的 `PubkeyAuthentication no`，会被 drop-in 正确覆盖，无需改动主文件。

## 测试

两套端到端测试，均在容器中完成。

**基础测试**（41 项断言）—— 在 Debian 13、Debian 12、Ubuntu 24.04 上分别验证：

- 复现商家镜像场景（出厂 `PubkeyAuthentication no`），验证脚本能自动开启密钥认证
- 验证 drop-in 确实压过主配置中的冲突项
- `--dry-run` 不产生任何实际改动
- 无密钥却要禁用密码时，护栏正确拒绝且配置不残留
- 改完端口后**真实用密钥登录成功**
- `--rollback` 完整还原到执行前状态
- 交互确认的提示确实可见，且 `y`/`yes`/`n`/回车/无效输入各自的处理符合预期

```bash
docker run --rm -v "$PWD:/work:ro" debian:13   bash /work/tests/run-test.sh
docker run --rm -v "$PWD:/work:ro" debian:12   bash /work/tests/run-test.sh
docker run --rm -v "$PWD:/work:ro" ubuntu:24.04 bash /work/tests/run-test.sh
```

**socket 激活测试**（28 项断言）—— 基础测试里 `systemctl` 是模拟的，测不到 socket 单元与
service 单元的真实交互，因此另起一个带真实 systemd 的容器验证：

- socket 激活模式下改端口真正生效，且经 socket 激活完成真实密钥登录
- **重启后端口保持不变**（含 `ssh.socket` 仅 enabled、当前未监听的情形）
- `sshd` 特权分离目录 `/run/sshd` 缺失时能自愈
- socket 模式下的 `--rollback` 能还原端口且不破坏 socket 激活形态

```bash
bash tests/run-test-socket.sh debian:13      # 默认镜像即 debian:13
bash tests/run-test-socket.sh debian:12
bash tests/run-test-socket.sh ubuntu:24.04
```

该测试需要 `docker --privileged`。Ubuntu 上「`ssh.socket` enabled 但 inactive」这一中间态
因单元依赖无法构造，对应用例会自动跳过。

实测结果：

| | 基础测试 | socket 激活测试 |
| --- | --- | --- |
| Debian 13 | 41/41 | 28/28 |
| Debian 12 | 41/41 | 28/28 |
| Ubuntu 24.04 | 41/41 | 21/21（跳过 1 组）|

## 兼容性说明

- **主要目标是 Debian 12 / 13**，测试与设计均以此为准。
- **Ubuntu 24.04** 已通过上表全部测试，可以用，但不是主要目标：其他 Ubuntu 版本（22.04、25.x 等）未经验证。
  需要留意的是，Ubuntu 22.10+ 默认由 `ssh.socket` 监听端口，这条路径的行为与 Debian 差别较大。
- **上述验证全部在容器中完成，没有真机记录**（Debian 与 Ubuntu 一样）。容器覆盖了真实 systemd
  与真实密钥登录，但仍不能替代真实 VPS——首次在生产机上使用时，请按[快速开始](#快速开始)里的推荐顺序
  操作（先不加 `-d`，另开终端验证密钥登录成功后再禁用密码），并保留一个可用的 VNC / 控制台通道。
- 其他发行版不阻止运行，但会先提示确认；遇到无法识别的环境会明确报错中止，而非默默做错。
- 使用 nftables / iptables 且存在过滤规则时，脚本**不会**自动改写规则（风险过高），而是提示手动确认端口已放行。
- `ssh.socket` 激活路径已在真实 systemd 环境验证（Debian 12 / 13、Ubuntu 24.04），见上节。
- 需要 root 权限，以及 `openssh-server` 与 `openssh-client`。

## 致谢

思路参考了 [P3TERX/SSH_Key_Installer](https://github.com/P3TERX/SSH_Key_Installer)，在其基础上重新实现。

## License

MIT
