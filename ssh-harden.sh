#!/usr/bin/env bash
#===============================================================================
# ssh-harden
#
# 在 Debian 12 / 13 上安装 SSH 公钥、修改端口、放行防火墙、禁用密码登录。
# 全程自我校验，任何环节失败自动回滚，避免把自己关在服务器外面。
#
# https://github.com/huangxm168/SSH-Harden
#
# 思路参考 P3TERX/SSH_Key_Installer，在其基础上重新实现。
#
# License: MIT
#===============================================================================

set -Eeuo pipefail

readonly HARDEN_VERSION="3.2.0"
readonly PROG="${0##*/}"

# ------------------------------------------------------------------ 路径常量 --
readonly SSHD_CONFIG="/etc/ssh/sshd_config"
readonly DROPIN_DIR="/etc/ssh/sshd_config.d"
# 序号取 10 是为了排在 cloud-init 等常见 drop-in（多为 50-）之前。
# sshd 采用首值优先，先读到的配置生效。
readonly DROPIN_FILE="${DROPIN_DIR}/10-ssh-harden.conf"
readonly SOCKET_DROPIN_DIR="/etc/systemd/system/ssh.socket.d"
readonly SOCKET_DROPIN_FILE="${SOCKET_DROPIN_DIR}/10-ssh-harden.conf"
readonly BACKUP_ROOT="/var/backups/ssh-harden"

# ------------------------------------------------------------------ 运行状态 --
DRY_RUN=0
ASSUME_YES=0
OVERWRITE=0
SKIP_FIREWALL=0
DO_ROLLBACK=0
DISABLE_PASSWORD=0
FORCE=0
SSH_PORT=""
TARGET_USER=""
KEY_SOURCES=()          # 形如 "github:P3TERX" / "url:https://..." / "file:/path" / "stdin:"
PUB_KEYS=()             # 校验通过的公钥文本
BACKUP_DIR=""
TRANSACTION=0           # 置 1 后出错才触发自动回滚
SSH_UNIT=""             # ssh 或 sshd
# socket 激活需要区分两种状态，只看其中一种都会出事：
#   SOCKET_ACTIVE  当前端口由 ssh.socket 持有，sshd_config 的 Port 完全无效
#   SOCKET_ENABLED 现在可能没在监听，但下次开机 ssh.socket 会接管端口
# 只判断 ACTIVE 会漏掉 enabled-but-inactive 的机器：改端口当场看着是成功的，
# 一重启 socket 就把端口抢回默认值，配合防火墙只放行新端口即彻底失联。
SOCKET_ACTIVE=0
SOCKET_ENABLED=0
ROLLED_BACK=0

# ------------------------------------------------------------------ 输出函数 --
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    readonly C_RED=$'\033[31m'    C_GRN=$'\033[1;32m'
    readonly C_YEL=$'\033[33m'    C_CYA=$'\033[36m'
    readonly C_DIM=$'\033[2m'     C_RST=$'\033[0m'
else
    readonly C_RED='' C_GRN='' C_YEL='' C_CYA='' C_DIM='' C_RST=''
fi

readonly CONFIRM_RULE="──────────────────────────────────────────────────────"
readonly CONFIRM_MAX_TRIES=3

info() { printf '%s[INFO]%s %s\n'  "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[WARN]%s %s\n'  "$C_YEL" "$C_RST" "$*" >&2; }
erro() { printf '%s[ERROR]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
step() { printf '\n%s==>%s %s\n'   "$C_CYA" "$C_RST" "$*"; }
note() { printf '%s     %s%s\n'    "$C_DIM" "$*" "$C_RST"; }

# 主动中止。若此时已经产生实际改动（事务已开始），必须先回滚再退出，
# 否则「被安全护栏拒绝」的场景会把半成品配置留在磁盘上——服务当时虽未重启、
# 不会立刻断连，但下次 sshd 重启就会按残留配置启动，等于埋下定时炸弹。
# 注意 exit 不触发 ERR trap，所以这里必须显式回滚。
die() {
    erro "$*"
    if [ "$TRANSACTION" -eq 1 ] && [ "$ROLLED_BACK" -eq 0 ] && \
       [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        ROLLED_BACK=1
        trap - ERR
        set +e
        erro "已产生改动，正在回滚..."
        restore_from "$BACKUP_DIR"
        erro "已回滚到执行前的状态：SSH 配置与现有连接均未改变，可放心重试"
    fi
    exit 1
}

# dry-run 模式下只打印不执行
run() {
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%s     [DRY-RUN] %s%s\n' "$C_DIM" "$*" "$C_RST"
        return 0
    fi
    "$@"
}

# 写文件（dry-run 下打印内容预览）
write_file() {
    local path="$1" content="$2" mode="${3:-644}"
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '%s     [DRY-RUN] 写入 %s (mode %s):%s\n' "$C_DIM" "$path" "$mode" "$C_RST"
        printf '%s       | %s%s\n' "$C_DIM" "${content//$'\n'/$'\n'       | }" "$C_RST"
        return 0
    fi
    printf '%s\n' "$content" > "$path"
    chmod "$mode" "$path"
}

# ------------------------------------------------------------------ 使用说明 --
usage() {
    cat <<EOF
ssh-harden ${HARDEN_VERSION}

用法:
  bash <(curl -fsSL <脚本地址>) [选项]
  ${PROG} [选项]

密钥来源（可重复、可组合，至少提供一个；--rollback 时除外）:
  -g, --github <用户名>    从 GitHub 获取公钥 (https://github.com/<用户名>.keys)
  -u, --url <URL>          从指定 URL 获取公钥
  -f, --file <路径>        从本地文件读取公钥
  -s, --stdin              从标准输入读取公钥

配置选项:
  -p, --port <端口>        修改 SSH 端口 (1-65535)
  -d, --disable-password   禁用密码登录（执行前会强制校验密钥确实可用）
  -o, --overwrite          覆盖模式，清空原有 authorized_keys 后写入
      --user <用户名>      目标用户，默认为 root
      --no-firewall        不自动放行防火墙端口

安全与调试:
  -n, --dry-run            预演模式，打印所有将要执行的改动但不实际执行
  -y, --yes                跳过所有交互确认（用于自动化）
      --force              跳过「当前会话是否为密钥登录」的强制确认（危险）
      --rollback           从最近一次备份还原配置并重启服务
  -h, --help               显示本帮助
  -V, --version            显示版本号

示例:
  # 安装公钥 + 改端口 + 自动放行防火墙（保留密码登录）
  ${PROG} -u https://example.com/id_ed25519.pub -p 54278

  # 先预演，确认无误后再实际执行
  ${PROG} -g octocat -p 54278 -d --dry-run
  ${PROG} -g octocat -p 54278 -d

  # 出问题时一键还原
  ${PROG} --rollback

设计说明:
  * 所有改动写入 ${DROPIN_FILE}，不污染主配置文件；
    若检测到 drop-in 未生效，自动回退为修改主配置文件。
  * 检测到 ssh.socket 已启用时（Ubuntu 22.10+ 默认如此），端口改为写入
    ${SOCKET_DROPIN_FILE}；
    即使它当前未监听也一并写入，避免重启后端口回退到旧值。
  * 每次改动前自动备份到 ${BACKUP_ROOT}/<时间戳>/。
  * 重启服务前执行 sshd -t 语法校验，重启后用 sshd -T 核对生效值，
    任一环节失败自动回滚。
  * -d 会在禁用密码前校验：密钥认证已启用、authorized_keys 内容合法、
    当前会话是否即为密钥登录。不满足则拒绝执行。
EOF
}

# ------------------------------------------------------------------ 参数解析 --
# 需要接参数的短选项
readonly OPTS_WITH_ARG="gufp"

# 展开组合短选项，兼容 getopts 的传统写法。很多一键脚本的用户已习惯这么写，
# 旧命令还可能被固化在短链接、文档或运维手册里，不应因换了实现方式而失效：
#   -ou <URL>    → -o -u <URL>
#   -p54278      → -p 54278
#   -op54278     → -o -p 54278
#   -dn          → -d -n
# 规则与 getopts 一致：从左往右逐字符展开，一旦遇到需要接参数的选项，
# 其后剩余字符即作为该选项的值（无剩余则由 parse_args 取下一个参数）。
EXPANDED_ARGS=()
expand_short_opts() {
    EXPANDED_ARGS=()
    local arg i c rest
    for arg in "$@"; do
        # 长选项（--xxx）、单个 -、以及非选项参数，一律原样保留
        if [[ "$arg" == --* ]] || [[ "$arg" != -?* ]]; then
            EXPANDED_ARGS+=("$arg")
            continue
        fi
        i=1
        while [ "$i" -lt "${#arg}" ]; do
            c="${arg:i:1}"
            if [[ "$OPTS_WITH_ARG" == *"$c"* ]]; then
                rest="${arg:i+1}"
                EXPANDED_ARGS+=("-$c")
                [ -n "$rest" ] && EXPANDED_ARGS+=("$rest")
                break
            fi
            EXPANDED_ARGS+=("-$c")
            i=$((i + 1))
        done
    done
}

parse_args() {
    while [ $# -gt 0 ]; do
        case "$1" in
            -g|--github)   [ $# -ge 2 ] || die "$1 需要一个参数"; KEY_SOURCES+=("github:$2"); shift 2 ;;
            -u|--url)      [ $# -ge 2 ] || die "$1 需要一个参数"; KEY_SOURCES+=("url:$2");    shift 2 ;;
            -f|--file)     [ $# -ge 2 ] || die "$1 需要一个参数"; KEY_SOURCES+=("file:$2");   shift 2 ;;
            -s|--stdin)    KEY_SOURCES+=("stdin:"); shift ;;
            -p|--port)     [ $# -ge 2 ] || die "$1 需要一个参数"; SSH_PORT="$2";    shift 2 ;;
            --user)        [ $# -ge 2 ] || die "$1 需要一个参数"; TARGET_USER="$2"; shift 2 ;;
            -d|--disable-password) DISABLE_PASSWORD=1; shift ;;
            -o|--overwrite)        OVERWRITE=1;        shift ;;
            --no-firewall)         SKIP_FIREWALL=1;    shift ;;
            -n|--dry-run)          DRY_RUN=1;          shift ;;
            -y|--yes)              ASSUME_YES=1;       shift ;;
            --force)               FORCE=1;            shift ;;
            --rollback)            DO_ROLLBACK=1;      shift ;;
            -h|--help)             usage; exit 0 ;;
            -V|--version)          printf '%s\n' "$HARDEN_VERSION"; exit 0 ;;
            --) shift; break ;;
            -*) die "未知选项: $1（用 --help 查看用法）" ;;
            *)  die "多余的参数: $1" ;;
        esac
    done

    [ "$DO_ROLLBACK" -eq 1 ] && return 0

    if [ ${#KEY_SOURCES[@]} -eq 0 ] && [ -z "$SSH_PORT" ] && [ "$DISABLE_PASSWORD" -eq 0 ]; then
        usage
        exit 1
    fi

    if [ -n "$SSH_PORT" ]; then
        [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "端口必须是数字: $SSH_PORT"
        [ "$SSH_PORT" -ge 1 ] && [ "$SSH_PORT" -le 65535 ] || die "端口超出范围 (1-65535): $SSH_PORT"
    fi

    [ -z "$TARGET_USER" ] && TARGET_USER="root"
}

# ------------------------------------------------------------------ 环境检测 --
require_root() {
    [ "$(id -u)" -eq 0 ] || die "需要 root 权限运行（请使用 sudo）"
}

detect_os() {
    [ -r /etc/os-release ] || die "无法读取 /etc/os-release，不支持的系统"

    # 必须在子 shell 中读取 os-release：它会定义 NAME / VERSION / ID 等变量，
    # 直接 source 会污染脚本命名空间，甚至与脚本自身的常量撞名而导致启动失败。
    local pretty id id_like
    pretty="$(. /etc/os-release 2>/dev/null; printf '%s' "${PRETTY_NAME:-}")"
    id="$(.  /etc/os-release 2>/dev/null; printf '%s' "${ID:-}")"
    id_like="$(. /etc/os-release 2>/dev/null; printf '%s' "${ID_LIKE:-}")"

    if [[ ! "${id_like} ${id}" =~ (debian|ubuntu) ]]; then
        # 此时尚未产生任何改动，选 n 是直接退出而非回滚，措辞要如实反映
        confirm \
"本脚本主要针对 Debian 12 / 13 测试，当前系统是 ${pretty:-未知}。
其他发行版的 sshd 配置结构、服务单元名称与防火墙工具都可能不同，
脚本的自我校验未必覆盖得到。" \
            "是否仍要在此系统上继续？" \
            "继续执行（风险自负）" \
            "退出，不做任何改动" \
            || die "已取消，未做任何改动"
    fi
    note "系统: ${pretty:-未知}"
}

detect_ssh_unit() {
    local u
    for u in ssh sshd; do
        if systemctl list-unit-files "${u}.service" >/dev/null 2>&1 &&
           systemctl cat "${u}.service" >/dev/null 2>&1; then
            SSH_UNIT="$u"
            break
        fi
    done
    [ -n "$SSH_UNIT" ] || die "找不到 ssh.service 或 sshd.service"

    if systemctl is-active --quiet ssh.socket 2>/dev/null; then
        SOCKET_ACTIVE=1
        SOCKET_ENABLED=1
        note "SSH 服务单元: ${SSH_UNIT}.service (socket 激活模式，端口由 ssh.socket 决定)"
        return 0
    fi

    # is-enabled 对 enabled / enabled-runtime 均返回 0，静态单元则另说，
    # 这里只关心「开机会不会被拉起来」，故统一按前缀匹配
    local sock_state
    sock_state="$(systemctl is-enabled ssh.socket 2>/dev/null || true)"
    case "$sock_state" in
        enabled*)
            SOCKET_ENABLED=1
            note "SSH 服务单元: ${SSH_UNIT}.service"
            warn "ssh.socket 已启用但当前未监听，重启后它会接管端口"
            ;;
        *)
            note "SSH 服务单元: ${SSH_UNIT}.service"
            ;;
    esac
}

check_prerequisites() {
    local miss=()
    command -v sshd       >/dev/null 2>&1 || miss+=("openssh-server")
    command -v ssh-keygen >/dev/null 2>&1 || miss+=("openssh-client")
    [ ${#miss[@]} -eq 0 ] || die "缺少依赖: ${miss[*]}"

    if [ ! -d /run/sshd ]; then
        ensure_runtime_dir || die "无法创建 /run/sshd（sshd 特权分离目录）"
        note "已补建缺失的 /run/sshd（sshd 特权分离目录）"
    fi
}

# sshd 启动时会检查特权分离目录，缺失则 sshd -t / -T 一律以 255 退出：
#   Missing privilege separation directory: /run/sshd
# 该目录由 ssh.service 的 RuntimeDirectory= 创建，systemd 会在服务停止时回收它。
# 两种情况下它都会不在：socket 激活模式下 sshd 按需启动、空闲时本就没在跑；
# 以及本脚本自己 stop ssh.service 之后。后者尤其阴险——sshd -T 取不到任何值，
# verify_effective_config 会把「配置其实完全正确」误判成未生效并触发回滚。
# 因此这里保持静默且可反复调用，在每次碰 sshd 之前兜一道底。
# /run 是 tmpfs 上的运行时目录，创建它不算配置改动，dry-run 下同样需要，
# 否则预演阶段的 sshd -T 全数失败，等于什么都验不了。
ensure_runtime_dir() {
    [ -d /run/sshd ] && return 0
    mkdir -p /run/sshd 2>/dev/null || return 1
    chmod 0755 /run/sshd 2>/dev/null || true
    return 0
}

# 在动任何配置之前先确认 sshd 当前配置是可解析的。
# 否则后续每一次 sshd -T 都会失败，触发一连串莫名其妙的回滚与误导性报错。
check_sshd_healthy() {
    ensure_runtime_dir || true
    local out rc=0
    out="$(sshd -t 2>&1)" || rc=$?
    [ "$rc" -eq 0 ] && return 0
    erro "sshd 现有配置未通过语法校验，脚本不能在此基础上安全工作:"
    printf '  %s\n' "$out" >&2
    die "请先手动修复上述问题（或执行 ${PROG} --rollback 还原）后重试"
}

# 读取 sshd 当前实际生效的配置值（比读配置文件可靠）
# 注意：awk 里绝不能用 exit 提前结束——sshd -T 有几十行输出，awk 提前退出会让
# sshd 收到 SIGPIPE（退出码 141），在 set -o pipefail 下会把整个赋值判定为失败。
# 这里改用标志位只取第一个匹配，并把输入读完。
sshd_effective() {
    local key="$1"
    # 兜底必须静默：本函数的返回值靠 stdout 传递，任何提示都会污染取到的值
    ensure_runtime_dir || true
    sshd -T 2>/dev/null | awk -v k="$key" 'tolower($1)==k && !seen {print $2; seen=1}'
}

# 交互确认。调用方必须同时说明「选 y 会怎样」「选 n 会怎样」——
# 这类提示只出现在高危操作前，用户看不懂就只能瞎猜，而猜错的代价是锁死或整单回滚。
#
# 提示整体分多行输出、每行都带换行符：既醒目，也不会因为「光标停在未结束的行尾」
# 而在网页控制台复制日志时整行丢失。至于提示为什么必须自己 printf 而不能用
# read -p，见下面循环里的说明——那才是它此前根本不显示的原因。
#
# 用法: confirm <上下文说明(可多行, 可为空)> <问题> <选 y 的后果> <选 n 的后果>
confirm() {
    local context="$1" question="$2" yes_desc="$3" no_desc="$4"
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ "$DRY_RUN" -eq 1 ] && return 0

    # 整块走 stderr：与 read -p 的提示同流，顺序不会因缓冲差异而错乱
    local line
    {
        printf '\n  %s%s%s\n' "$C_YEL" "$CONFIRM_RULE" "$C_RST"
        printf '  %s需要你确认%s\n'  "$C_YEL" "$C_RST"
        printf '  %s%s%s\n'   "$C_YEL" "$CONFIRM_RULE" "$C_RST"
        if [ -n "$context" ]; then
            while IFS= read -r line; do printf '  %s\n' "$line"; done <<< "$context"
            printf '\n'
        fi
        printf '  %s%s%s\n\n' "$C_CYA" "$question" "$C_RST"
        printf '    y / yes   %s\n' "$yes_desc"
        printf '    n / no    %s（直接回车同此）\n' "$no_desc"
        printf '  %s%s%s\n' "$C_YEL" "$CONFIRM_RULE" "$C_RST"
    } >&2

    # 只有「无法识别的输入」才重试；空输入是明确的拒绝，不再追问
    local reply try=0
    while [ "$try" -lt "$CONFIRM_MAX_TRIES" ]; do
        try=$((try + 1))
        # 提示必须自己 printf，不能用 read -p：read -p 的提示同样写 stderr，
        # 而为了压掉 /dev/tty 不存在时的报错必须带 2>/dev/null，那会把提示一并吞掉，
        # 用户看到的就是脚本无声挂起、不知道在等什么——这正是 3.1.0 及之前的真实表现。
        printf '  %s请输入 [y/n]: %s' "$C_CYA" "$C_RST" >&2
        if ! read -r reply < /dev/tty 2>/dev/null; then
            printf '\n' >&2
            warn "检测不到终端输入，已按取消处理"
            note "自动化场景请加 --yes（使用前请确认你已了解上述风险）" >&2
            return 1
        fi
        case "$reply" in
            y|Y|yes|YES|Yes) return 0 ;;
            n|N|no|NO|No|"") return 1 ;;
            *)
                [ "$try" -lt "$CONFIRM_MAX_TRIES" ] &&
                    warn "无法识别的输入「${reply}」，请输入 y 或 n"
                ;;
        esac
    done
    warn "连续 ${CONFIRM_MAX_TRIES} 次无法识别输入，已按取消处理"
    return 1
}

# 动手前先把「将要发生什么」摊开说清楚，避免用户执行到一半才反应过来。
# 只打印、不拦截：加一道确认会让交互式使用多一次打断，而 -y 场景下又形同虚设。
print_plan() {
    step "执行计划"
    local n=0
    if [ ${#PUB_KEYS[@]} -gt 0 ]; then
        n=$((n + 1))
        note "${n}. 安装 ${#PUB_KEYS[@]} 个公钥到用户 ${TARGET_USER}$([ "$OVERWRITE" -eq 1 ] && printf '（覆盖模式，会清空原有内容）')"
    fi
    if [ -n "$SSH_PORT" ]; then
        n=$((n + 1))
        local cur_port; cur_port="$(sshd_effective port)"
        note "${n}. 修改 SSH 端口: ${cur_port:-未知} → ${SSH_PORT}"
        if [ "$SKIP_FIREWALL" -eq 1 ]; then
            note "   （已指定 --no-firewall，不会自动放行防火墙，请自行确认端口可达）"
        else
            n=$((n + 1))
            note "${n}. 放行防火墙 ${SSH_PORT}/tcp"
        fi
    fi
    if [ "$DISABLE_PASSWORD" -eq 1 ]; then
        n=$((n + 1))
        note "${n}. 禁用密码登录（执行前会强制校验密钥可用，不满足则中止并回滚）"
    fi
    note "改动前会自动备份，任一环节失败自动回滚；随时可用 ${PROG} --rollback 还原"
}

# ------------------------------------------------------------------ 备份还原 --
create_backup() {
    local ts; ts="$(date +%Y%m%d-%H%M%S)"
    BACKUP_DIR="${BACKUP_ROOT}/${ts}"

    if [ "$DRY_RUN" -eq 1 ]; then
        note "[DRY-RUN] 将备份配置到 ${BACKUP_DIR}/"
        return 0
    fi

    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_ROOT" "$BACKUP_DIR"

    [ -f "$SSHD_CONFIG" ] && cp -a "$SSHD_CONFIG" "${BACKUP_DIR}/sshd_config"
    [ -d "$DROPIN_DIR" ]  && cp -a "$DROPIN_DIR"  "${BACKUP_DIR}/sshd_config.d"
    [ -d "$SOCKET_DROPIN_DIR" ] && cp -a "$SOCKET_DROPIN_DIR" "${BACKUP_DIR}/ssh.socket.d"

    local akf; akf="$(authorized_keys_path)"
    if [ -f "$akf" ]; then
        cp -a "$akf" "${BACKUP_DIR}/authorized_keys"
        printf '%s\n' "$akf" > "${BACKUP_DIR}/authorized_keys.path"
    fi

    # 记录还原所需的元信息
    {
        printf 'timestamp=%s\n' "$ts"
        printf 'ssh_unit=%s\n'  "$SSH_UNIT"
        printf 'user=%s\n'      "$TARGET_USER"
    } > "${BACKUP_DIR}/meta"

    ln -sfn "$BACKUP_DIR" "${BACKUP_ROOT}/latest"
    info "已备份到 ${BACKUP_DIR}/"
}

restore_from() {
    local dir="$1"
    [ -d "$dir" ] || die "备份目录不存在: $dir"

    step "从备份还原: $dir"

    if [ -f "${dir}/sshd_config" ]; then
        run cp -a "${dir}/sshd_config" "$SSHD_CONFIG"
        note "已还原 $SSHD_CONFIG"
    fi

    if [ -d "${dir}/sshd_config.d" ]; then
        run rm -rf "$DROPIN_DIR"
        run cp -a "${dir}/sshd_config.d" "$DROPIN_DIR"
        note "已还原 $DROPIN_DIR"
    else
        # 备份时该目录不存在，说明是脚本新建的，应删除
        [ -f "$DROPIN_FILE" ] && { run rm -f "$DROPIN_FILE"; note "已移除 $DROPIN_FILE"; }
    fi

    if [ -d "${dir}/ssh.socket.d" ]; then
        run rm -rf "$SOCKET_DROPIN_DIR"
        run cp -a "${dir}/ssh.socket.d" "$SOCKET_DROPIN_DIR"
        run systemctl daemon-reload
        note "已还原 $SOCKET_DROPIN_DIR"
    elif [ -f "$SOCKET_DROPIN_FILE" ]; then
        run rm -f "$SOCKET_DROPIN_FILE"
        run systemctl daemon-reload
        note "已移除 $SOCKET_DROPIN_FILE"
    fi

    if [ -f "${dir}/authorized_keys" ] && [ -f "${dir}/authorized_keys.path" ]; then
        local akf; akf="$(cat "${dir}/authorized_keys.path")"
        run cp -a "${dir}/authorized_keys" "$akf"
        note "已还原 $akf"
    fi

    ensure_runtime_dir || true
    if run sshd -t; then
        restart_ssh_stack
        info "服务已重启，还原完成"
    else
        die "还原后的配置仍未通过语法校验，请手动检查（可能需要通过 VNC 控制台介入）"
    fi
}

do_rollback() {
    local latest="${BACKUP_ROOT}/latest"
    [ -e "$latest" ] || die "找不到备份（${latest}），无法还原"
    restore_from "$(readlink -f "$latest")"
}

# 出错时自动回滚
on_error() {
    local line="$1"
    [ "$ROLLED_BACK" -eq 1 ] && return
    ROLLED_BACK=1
    erro "执行失败（第 ${line} 行），开始自动回滚..."
    if [ "$TRANSACTION" -eq 1 ] && [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
        # 回滚过程本身不再触发 trap
        trap - ERR
        set +e
        restore_from "$BACKUP_DIR"
        erro "已回滚到执行前的状态"
    else
        erro "尚未产生实际改动，无需回滚"
    fi
    exit 1
}

# ------------------------------------------------------------------ 密钥处理 --
user_home() {
    local h; h="$(getent passwd "$1" | cut -d: -f6)"
    [ -n "$h" ] || die "用户不存在: $1"
    printf '%s\n' "$h"
}

authorized_keys_path() {
    local home; home="$(user_home "$TARGET_USER")"
    # 以 sshd 实际生效的 AuthorizedKeysFile 为准，取第一个路径
    # （同 sshd_effective，awk 不能用 exit，否则 SIGPIPE 会让赋值失败）
    local akf; akf="$(sshd_effective authorizedkeysfile)"
    [ -z "$akf" ] && akf=".ssh/authorized_keys"
    case "$akf" in
        /*) printf '%s\n' "${akf//\%h/$home}" ;;
        *)  printf '%s\n' "${home}/${akf}" ;;
    esac
}

# 校验单行是否为合法公钥
is_valid_pubkey() {
    local line="$1" tmp rc
    tmp="$(mktemp)"
    printf '%s\n' "$line" > "$tmp"
    ssh-keygen -l -f "$tmp" >/dev/null 2>&1; rc=$?
    rm -f "$tmp"
    return $rc
}

fetch_from_source() {
    local src="$1" kind="${1%%:*}" arg="${1#*:}" raw=""
    case "$kind" in
        github)
            [ -n "$arg" ] || die "GitHub 用户名不能为空"
            note "从 GitHub 获取: $arg"
            raw="$(curl -fsSL --max-time 30 "https://github.com/${arg}.keys")" \
                || die "GitHub 公钥获取失败: $arg"
            [ -n "$raw" ] || die "GitHub 用户 ${arg} 没有配置公钥"
            ;;
        url)
            [ -n "$arg" ] || die "URL 不能为空"
            note "从 URL 获取: $arg"
            raw="$(curl -fsSL --max-time 30 "$arg")" || die "URL 公钥获取失败: $arg"
            ;;
        file)
            [ -r "$arg" ] || die "文件不可读: $arg"
            note "从文件读取: $arg"
            raw="$(cat -- "$arg")"
            ;;
        stdin)
            note "从标准输入读取公钥"
            raw="$(cat)"
            ;;
        *) die "未知的密钥来源: $src" ;;
    esac

    local line count=0
    while IFS= read -r line; do
        # 跳过空行与注释
        [ -z "${line// /}" ] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        if is_valid_pubkey "$line"; then
            PUB_KEYS+=("$line")
            count=$((count + 1))
        else
            warn "忽略无法识别的内容: ${line:0:48}..."
        fi
    done <<< "$raw"

    [ "$count" -gt 0 ] || die "来源 ${src} 未获得任何合法公钥（可能返回了错误页面）"
    note "获得 ${count} 个合法公钥"
}

collect_keys() {
    [ ${#KEY_SOURCES[@]} -eq 0 ] && return 0
    step "获取并校验公钥"
    local src
    for src in "${KEY_SOURCES[@]}"; do
        fetch_from_source "$src"
    done

    local k
    for k in "${PUB_KEYS[@]}"; do
        local tmp; tmp="$(mktemp)"
        printf '%s\n' "$k" > "$tmp"
        note "  $(ssh-keygen -l -f "$tmp" 2>/dev/null)"
        rm -f "$tmp"
    done
}

install_keys() {
    [ ${#PUB_KEYS[@]} -eq 0 ] && return 0
    step "安装公钥到用户 ${TARGET_USER}"

    local home akf ssh_dir
    home="$(user_home "$TARGET_USER")"
    akf="$(authorized_keys_path)"
    ssh_dir="$(dirname "$akf")"

    if [ "$OVERWRITE" -eq 1 ] && [ -s "$akf" ]; then
        local old_lines
        old_lines="$(grep -cve '^\s*$' "$akf" 2>/dev/null || echo 0)"
        confirm \
"覆盖模式（-o）会先清空 ${akf} 中已有的 ${old_lines} 行内容，再写入本次获取的公钥。
其他人或其他设备的公钥若在其中，将一并失效。
原文件已备份到 ${BACKUP_DIR}/authorized_keys，事后可用 ${PROG} --rollback 还原。" \
            "确认清空原有内容并写入新公钥？" \
            "清空后写入本次公钥" \
            "取消并回滚全部改动" \
            || die "已取消。如果只是想追加公钥而非替换，去掉 -o 重新执行即可"
    fi

    if [ "$DRY_RUN" -eq 0 ]; then
        mkdir -p "$ssh_dir"
        chmod 700 "$ssh_dir"
        chown "${TARGET_USER}:" "$ssh_dir" 2>/dev/null || true
        [ -f "$akf" ] || : > "$akf"
    else
        note "[DRY-RUN] 确保目录存在: $ssh_dir (700)"
    fi

    # 组装最终内容：覆盖模式从空开始，否则保留原有内容
    local existing="" final=""
    if [ "$OVERWRITE" -eq 0 ] && [ -f "$akf" ] && [ "$DRY_RUN" -eq 0 ]; then
        existing="$(cat "$akf")"
    fi

    final="$existing"
    local k added=0 skipped=0
    for k in "${PUB_KEYS[@]}"; do
        # 按密钥主体去重（忽略注释字段差异）
        local body; body="$(awk '{print $1" "$2}' <<< "$k")"
        if [ -n "$final" ] && grep -qF -- "$body" <<< "$final"; then
            skipped=$((skipped + 1))
            continue
        fi
        if [ -n "$final" ]; then
            final="${final}"$'\n'"${k}"
        else
            final="${k}"
        fi
        added=$((added + 1))
    done

    write_file "$akf" "$final" 600
    if [ "$DRY_RUN" -eq 0 ]; then
        chown "${TARGET_USER}:" "$akf" 2>/dev/null || true
    fi

    info "已写入 ${akf}（新增 ${added} 个，跳过重复 ${skipped} 个）"
}

# ------------------------------------------------------------ sshd 配置写入 --
# 期望生效的配置项，形如 "key value"
declare -a DESIRED_CONFIG=()

build_desired_config() {
    [ -n "$SSH_PORT" ] && DESIRED_CONFIG+=("Port ${SSH_PORT}")

    # 安装了密钥、或准备禁用密码时，都必须显式启用密钥认证。
    # 部分商家镜像（如 VMISS 的 Debian 12）出厂预置 PubkeyAuthentication no，
    # 若只关密码而不开密钥，会导致所有认证方式同时失效、彻底锁死。
    if [ ${#PUB_KEYS[@]} -gt 0 ] || [ "$DISABLE_PASSWORD" -eq 1 ]; then
        DESIRED_CONFIG+=("PubkeyAuthentication yes")
    fi

    [ "$DISABLE_PASSWORD" -eq 1 ]   && DESIRED_CONFIG+=("PasswordAuthentication no")
    [ "$DISABLE_PASSWORD" -eq 1 ]   && DESIRED_CONFIG+=("KbdInteractiveAuthentication no")
    # 禁用密码时，root 登录方式收紧为仅密钥
    if [ "$DISABLE_PASSWORD" -eq 1 ] && [ "$TARGET_USER" = "root" ]; then
        DESIRED_CONFIG+=("PermitRootLogin prohibit-password")
    fi
    return 0
}

supports_dropin() {
    [ -d "$DROPIN_DIR" ] || return 1
    grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG"
}

write_dropin_config() {
    local content="# Managed by ssh-harden ${HARDEN_VERSION}
# 本文件由脚本自动生成，如需还原请执行: ${PROG} --rollback
"
    local item
    for item in "${DESIRED_CONFIG[@]}"; do
        content="${content}${item}
"
    done

    [ "$DRY_RUN" -eq 0 ] && mkdir -p "$DROPIN_DIR"
    write_file "$DROPIN_FILE" "$content" 644
    note "已写入 $DROPIN_FILE"
}

# drop-in 未生效时，直接改主配置：注释掉冲突行并追加正确值
patch_main_config() {
    warn "drop-in 未生效（Include 位置靠后或不存在），改为直接修改主配置文件"

    local item key
    for item in "${DESIRED_CONFIG[@]}"; do
        key="${item%% *}"
        # 注释掉所有已生效的同名配置行（精确匹配行首关键字）
        run sed -i -E "s@^[[:space:]]*(${key}[[:space:]].*)\$@# [ssh-harden] \1@I" "$SSHD_CONFIG"
    done

    local block
    block="
# ---- Managed by ssh-harden ${HARDEN_VERSION} ----
$(printf '%s\n' "${DESIRED_CONFIG[@]}")
# ---- end ssh-harden ----"

    if [ "$DRY_RUN" -eq 1 ]; then
        note "[DRY-RUN] 将向 ${SSHD_CONFIG} 追加:"
        printf '%s     | %s%s\n' "$C_DIM" "${block//$'\n'/$'\n'       | }" "$C_RST"
    else
        printf '%s\n' "$block" >> "$SSHD_CONFIG"
    fi
    note "已更新 $SSHD_CONFIG"
}

# OpenSSH 部分取值存在同义词，且 sshd -T 只输出其中一种规范形式，
# 直接做字符串比较会把「已正确生效」误判为「未生效」。
# 例如写入 PermitRootLogin prohibit-password，sshd -T 会报告 without-password。
normalize_cfg_value() {
    case "$1" in
        without-password) printf 'prohibit-password' ;;
        *)                printf '%s' "$1" ;;
    esac
}

# 校验期望值是否真正生效，返回不符项
verify_effective_config() {
    local failed=()
    local item key want got want_n got_n
    for item in "${DESIRED_CONFIG[@]}"; do
        key="$(tr '[:upper:]' '[:lower:]' <<< "${item%% *}")"
        want="$(tr '[:upper:]' '[:lower:]' <<< "${item#* }")"
        got="$(tr '[:upper:]' '[:lower:]' <<< "$(sshd_effective "$key")")"
        want_n="$(normalize_cfg_value "$want")"
        got_n="$(normalize_cfg_value "$got")"
        # 报告时仍显示原始值，便于排查
        [ "$got_n" = "$want_n" ] || failed+=("${key}: 期望 ${want}, 实际 ${got:-<空>}")
    done
    if [ ${#failed[@]} -gt 0 ]; then
        printf '%s\n' "${failed[@]}"
        return 1
    fi
    return 0
}

apply_sshd_config() {
    [ ${#DESIRED_CONFIG[@]} -eq 0 ] && return 0
    step "写入 sshd 配置"
    note "目标配置: ${DESIRED_CONFIG[*]}"

    if supports_dropin; then
        write_dropin_config
    else
        patch_main_config
        return 0
    fi

    # dry-run 无法验证真实生效值，跳过
    [ "$DRY_RUN" -eq 1 ] && return 0

    # 语法必须先过，否则 sshd -T 无意义
    ensure_runtime_dir || true
    sshd -t 2>/dev/null || die "写入 drop-in 后语法校验失败"

    local bad
    if ! bad="$(verify_effective_config)"; then
        note "drop-in 生效情况: ${bad//$'\n'/; }"
        patch_main_config
    else
        note "drop-in 已生效"
    fi
}

# ------------------------------------------------------ socket 激活端口处理 --
apply_socket_port() {
    # 只要 ssh.socket 已启用就得改，哪怕它当前没在监听——否则重启后端口回退
    [ "$SOCKET_ENABLED" -eq 1 ] || return 0
    [ -n "$SSH_PORT" ] || return 0

    step "配置 ssh.socket 监听端口"
    if [ "$SOCKET_ACTIVE" -eq 1 ]; then
        warn "当前为 socket 激活模式，sshd_config 的 Port 指令会被忽略，需修改 socket 单元"
    else
        warn "ssh.socket 已启用（当前未监听），同步修改 socket 单元，避免重启后端口回退"
    fi

    local content="[Socket]
# Managed by ssh-harden ${HARDEN_VERSION}
# 先清空默认监听，再设置新端口
ListenStream=
ListenStream=${SSH_PORT}"

    [ "$DRY_RUN" -eq 0 ] && mkdir -p "$SOCKET_DROPIN_DIR"
    write_file "$SOCKET_DROPIN_FILE" "$content" 644
    run systemctl daemon-reload
    note "已写入 $SOCKET_DROPIN_FILE"
}

# ---------------------------------------------------------------- 防火墙 ----
# 逐个探测防火墙。所有命令输出先落到变量再匹配，避免 cmd | grep -q 在
# pipefail 下因 SIGPIPE（grep 提前退出）或 grep 无匹配而被误判为「未启用」。
detect_firewall() {
    local out

    if command -v ufw >/dev/null 2>&1; then
        out="$(ufw status 2>/dev/null || true)"
        if grep -qi '^Status: active' <<< "$out"; then printf 'ufw\n'; return 0; fi
    fi

    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        printf 'firewalld\n'; return 0
    fi

    if command -v nft >/dev/null 2>&1; then
        out="$(nft list ruleset 2>/dev/null || true)"
        if grep -q 'hook input' <<< "$out"; then printf 'nftables\n'; return 0; fi
    fi

    if command -v iptables >/dev/null 2>&1; then
        out="$(iptables -S INPUT 2>/dev/null || true)"
        if grep -qE '^-P INPUT (DROP|REJECT)' <<< "$out"; then printf 'iptables\n'; return 0; fi
    fi

    printf 'none\n'
}

open_firewall_port() {
    [ -n "$SSH_PORT" ] || return 0
    [ "$SKIP_FIREWALL" -eq 1 ] && { note "已跳过防火墙配置 (--no-firewall)"; return 0; }

    step "放行防火墙端口 ${SSH_PORT}"
    local fw; fw="$(detect_firewall)"

    case "$fw" in
        ufw)
            run ufw allow "${SSH_PORT}/tcp"
            info "ufw: 已放行 ${SSH_PORT}/tcp"
            ;;
        firewalld)
            run firewall-cmd --permanent --add-port="${SSH_PORT}/tcp"
            run firewall-cmd --reload
            info "firewalld: 已放行 ${SSH_PORT}/tcp"
            ;;
        nftables|iptables)
            confirm \
"检测到 ${fw} 且存在过滤规则，但自动改写这类规则风险太高，脚本不会代劳。
若 ${SSH_PORT}/tcp 实际没有放行，改完端口重启服务的瞬间就会失联。

建议：另开一个终端手动放行 ${SSH_PORT}/tcp，确认无误后再回来选 y。" \
                "${SSH_PORT}/tcp 是否已经放行？" \
                "已放行，继续修改端口" \
                "取消并回滚全部改动" \
                || die "已取消。请先手动放行 ${SSH_PORT}/tcp 后重试；若确认无需放行，可加 --no-firewall"
            ;;
        none)
            note "未检测到启用中的防火墙，无需放行"
            ;;
    esac
}

# ------------------------------------------------------------ 安全护栏 ------
# 判断当前 SSH 会话是否通过公钥认证登录
current_session_auth_method() {
    [ -n "${SSH_CONNECTION:-}" ] || { printf 'unknown\n'; return; }

    local cport; cport="$(awk '{print $2}' <<< "$SSH_CONNECTION")"
    [ -n "$cport" ] || { printf 'unknown\n'; return; }

    local logs=""
    if command -v journalctl >/dev/null 2>&1; then
        logs="$(journalctl -u "${SSH_UNIT}.service" --since '-2 days' --no-pager 2>/dev/null || true)"
    fi
    [ -z "$logs" ] && [ -r /var/log/auth.log ] && logs="$(cat /var/log/auth.log 2>/dev/null || true)"
    [ -z "$logs" ] && { printf 'unknown\n'; return; }

    # grep 无匹配时返回 1，配合 pipefail 会让整个赋值失败，故加 || true
    local line
    line="$(grep -E "Accepted .* port ${cport}( |$)" <<< "$logs" | tail -1 || true)"
    if   grep -q 'Accepted publickey' <<< "$line"; then printf 'publickey\n'
    elif grep -q 'Accepted password'  <<< "$line"; then printf 'password\n'
    else printf 'unknown\n'
    fi
}

# 禁用密码前的强制校验：三重证据
assert_key_auth_ready() {
    [ "$DISABLE_PASSWORD" -eq 1 ] || return 0

    step "禁用密码前的安全校验"

    if [ "$DRY_RUN" -eq 1 ]; then
        note "[DRY-RUN] 将校验密钥认证可用性后再禁用密码"
        return 0
    fi

    # 证据一：sshd 实际启用了公钥认证
    local pk; pk="$(sshd_effective pubkeyauthentication)"
    [ "$pk" = "yes" ] || die "PubkeyAuthentication 当前为 ${pk:-<空>}，禁用密码会导致无法登录，已中止"
    note "✓ PubkeyAuthentication = yes"

    # 证据二：authorized_keys 内容与权限合法
    local akf; akf="$(authorized_keys_path)"
    [ -f "$akf" ] || die "找不到 ${akf}，禁用密码会导致无法登录，已中止"

    local valid=0 line
    while IFS= read -r line; do
        [ -z "${line// /}" ] && continue
        [[ "$line" =~ ^[[:space:]]*# ]] && continue
        is_valid_pubkey "$line" && valid=$((valid + 1))
    done < "$akf"
    [ "$valid" -gt 0 ] || die "${akf} 中没有合法公钥，已中止"
    note "✓ ${akf} 含 ${valid} 个合法公钥"

    local perm; perm="$(stat -c '%a' "$akf")"
    [ "$perm" -le 600 ] || die "${akf} 权限 ${perm} 过于宽松，sshd 会拒绝使用，已中止"
    local dperm; dperm="$(stat -c '%a' "$(dirname "$akf")")"
    [ "$dperm" -le 700 ] || die "$(dirname "$akf") 权限 ${dperm} 过于宽松，已中止"
    note "✓ 权限检查通过 (${akf} ${perm}, 目录 ${dperm})"

    local owner; owner="$(stat -c '%U' "$akf")"
    [ "$owner" = "$TARGET_USER" ] || warn "${akf} 属主为 ${owner}，而目标用户是 ${TARGET_USER}"

    # 证据三：当前会话本身是否即为密钥登录（最硬的证据）
    local auth; auth="$(current_session_auth_method)"
    case "$auth" in
        publickey)
            note "✓ 当前 SSH 会话即通过密钥认证登录，密钥链路已确认可用"
            ;;
        password)
            if [ "$FORCE" -eq 1 ]; then
                warn "当前会话是密码登录，脚本无法确认密钥可用；但已指定 --force，跳过确认"
            else
                confirm \
"当前 SSH 会话是通过【密码】登录的，脚本无法确认你的密钥确实可用。
若密钥实际不可用，禁用密码后你将彻底失去 SSH 访问，只能通过 VNC 控制台救援。

建议：另开一个终端用密钥登录成功，然后在那个会话里重新执行本命令——
脚本会自动识别出你已是密钥登录，届时不再询问。" \
                    "是否继续禁用密码登录？" \
                    "继续禁用（我已确认密钥可用）" \
                    "取消并回滚全部改动" \
                    || die "已取消。建议先用密钥登录成功后再重试；确有把握也可用 --force 跳过此检查"
            fi
            ;;
        *)
            # 这两种情形的共同点是「拿不到证据」，而非「证据表明有问题」，
            # 所以更要把话说清楚：用户看到的往往只有一句 warn，不知道自己该干什么
            local why
            if [ -z "${SSH_CONNECTION:-}" ]; then
                why="当前不在 SSH 会话中（本地控制台 / 容器），脚本无法验证你的密钥登录链路是否真的通。"
            else
                # Debian 13 起默认不再安装 rsyslog，/var/log/auth.log 不存在，
                # 只剩 journald 一条路；若 journal 也读不到就只能靠人工确认
                why="无法从日志判断当前会话的认证方式（journald 无相关记录，且无 /var/log/auth.log）。"
            fi
            if [ "$FORCE" -eq 1 ]; then
                warn "${why}但已指定 --force，跳过确认"
            else
                confirm \
"${why}
若密钥实际不可用，禁用密码后你将彻底失去 SSH 访问，只能通过 VNC 控制台救援。

建议：先去掉 -d 执行一次（只装密钥、改端口），用密钥登录成功后，
再在那个 SSH 会话里加上 -d 重新执行——脚本届时能自动确认密钥可用，不再询问。" \
                    "是否继续禁用密码登录？" \
                    "继续禁用（我已确认密钥可用）" \
                    "取消并回滚全部改动" \
                    || die "已取消。建议先去掉 -d 装好密钥并实际登录验证，再回来执行禁用密码"
            fi
            ;;
    esac
}

# ---------------------------------------------------------- 服务重启与验证 --
# socket 激活模式下的重启顺序是唯一正确解，顺序反了必然失败：
# 先 restart ssh.service 会让 sshd 自己抢占端口，随后 systemd 拒绝 socket 重新监听
#   ssh.socket: Socket service ssh.service already active, refusing.
#   Failed to listen on ssh.socket
# 结果是新端口从未生效。必须先 stop 服务把端口让出来，再让 socket 重新 bind。
# ssh.service 带 KillMode=process，停掉 listener 不会断开已建立的 SSH 会话；
# socket 模式下也无需再 start 服务，来一个连接 systemd 自会拉起。
restart_ssh_stack() {
    if [ "$SOCKET_ACTIVE" -eq 1 ]; then
        run systemctl stop "${SSH_UNIT}.service"
        # 服务一停，systemd 就把 RuntimeDirectory（/run/sshd）回收了，
        # 后续 sshd -t / -T 会全数失败，必须立刻补回来
        ensure_runtime_dir || true
        run systemctl restart ssh.socket
    else
        run systemctl restart "${SSH_UNIT}.service"
    fi
}

restart_and_verify() {
    [ ${#DESIRED_CONFIG[@]} -eq 0 ] && return 0

    step "校验配置并重启服务"

    if [ "$DRY_RUN" -eq 1 ]; then
        if [ "$SOCKET_ACTIVE" -eq 1 ]; then
            note "[DRY-RUN] 将执行: sshd -t && systemctl stop ${SSH_UNIT}.service && systemctl restart ssh.socket"
        else
            note "[DRY-RUN] 将执行: sshd -t && systemctl restart ${SSH_UNIT}.service"
        fi
        return 0
    fi

    ensure_runtime_dir || true
    sshd -t || die "sshd 配置语法校验失败，已中止（不会重启服务）"
    note "✓ sshd -t 语法校验通过"

    restart_ssh_stack
    sleep 1

    # socket 激活模式下 sshd 是按需启动的，空闲时 ssh.service 必然是 inactive，
    # 用它判断存活会把正常状态误判成重启失败，这里要改看 socket 单元。
    if [ "$SOCKET_ACTIVE" -eq 1 ]; then
        systemctl is-active --quiet ssh.socket ||
            die "ssh.socket 重启后未处于监听状态"
        note "✓ ssh.socket 监听中（sshd 由连接触发启动）"
    else
        systemctl is-active --quiet "${SSH_UNIT}.service" ||
            die "${SSH_UNIT}.service 重启后未处于运行状态"
        note "✓ ${SSH_UNIT}.service 运行中"
    fi

    local bad
    if ! bad="$(verify_effective_config)"; then
        erro "配置未按预期生效:"
        printf '  %s\n' "$bad" >&2
        return 1
    fi
    note "✓ 配置已按预期生效"

    # 确认端口确实在监听（先取输出再匹配，避免管道 SIGPIPE 误判）
    if [ -n "$SSH_PORT" ] && command -v ss >/dev/null 2>&1; then
        local listening
        listening="$(ss -ltn 2>/dev/null || true)"
        if grep -qE "[:.]${SSH_PORT}([[:space:]]|\$)" <<< "$listening"; then
            note "✓ 端口 ${SSH_PORT} 已在监听"
        else
            erro "端口 ${SSH_PORT} 未在监听"
            return 1
        fi
    fi
}

print_summary() {
    step "完成"

    local port pk pw
    if [ "$DRY_RUN" -eq 1 ]; then
        printf '  预演结束，未做任何实际改动。去掉 --dry-run 即可实际执行。\n'
        return 0
    fi

    port="$(sshd_effective port)"
    pk="$(sshd_effective pubkeyauthentication)"
    pw="$(sshd_effective passwordauthentication)"

    printf '  当前生效配置:\n'
    printf '    端口              : %s\n' "${port:-未知}"
    if [ "$SOCKET_ACTIVE" -eq 1 ]; then
        printf '    端口来源          : ssh.socket 单元（sshd_config 的 Port 被忽略）\n'
    elif [ "$SOCKET_ENABLED" -eq 1 ]; then
        printf '    端口来源          : %s.service；ssh.socket 已启用，重启后接管（已同步配置）\n' "$SSH_UNIT"
    fi
    printf '    密钥认证          : %s\n' "${pk:-未知}"
    printf '    密码认证          : %s\n' "${pw:-未知}"
    printf '    authorized_keys   : %s\n' "$(authorized_keys_path)"
    printf '    配置备份          : %s\n' "${BACKUP_DIR:-无}"
    printf '\n'

    if [ "$pw" = "no" ]; then
        printf '  %s重要%s: 密码登录已禁用，请立刻用密钥新开一个连接验证:\n' "$C_YEL" "$C_RST"
        printf '    ssh -p %s -i <你的私钥> %s@<服务器IP>\n' "${port}" "$TARGET_USER"
        printf '  在验证成功前，请不要关闭当前会话。\n'
        printf '  如需还原: %s --rollback\n' "$PROG"
    elif [ -n "$SSH_PORT" ]; then
        printf '  请用新端口验证连接后再关闭当前会话:\n'
        printf '    ssh -p %s %s@<服务器IP>\n' "${port}" "$TARGET_USER"
        printf '  如需还原: %s --rollback\n' "$PROG"
    fi
}

# ------------------------------------------------------------------ 主流程 --
main() {
    expand_short_opts "$@"
    parse_args "${EXPANDED_ARGS[@]}"
    require_root
    check_prerequisites
    detect_ssh_unit

    # 健康检查放在 rollback 之后：配置已经坏掉时，--rollback 正是补救手段，
    # 不该被这道检查挡在门外
    if [ "$DO_ROLLBACK" -eq 1 ]; then
        do_rollback
        exit 0
    fi

    check_sshd_healthy
    detect_os

    printf '%sssh-harden %s%s' "$C_CYA" "$HARDEN_VERSION" "$C_RST"
    [ "$DRY_RUN" -eq 1 ] && printf ' %s(预演模式)%s' "$C_YEL" "$C_RST"
    printf '\n'

    collect_keys
    build_desired_config
    print_plan

    # 从这里开始产生实际改动，启用出错自动回滚
    create_backup
    TRANSACTION=1
    trap 'on_error $LINENO' ERR

    install_keys
    apply_sshd_config
    apply_socket_port

    # 防火墙必须在重启 sshd 之前放行，否则改端口瞬间即失联
    open_firewall_port

    # 密码禁用的校验放在配置写入之后、重启之前：
    # 此时 PubkeyAuthentication 已写入配置，sshd -T 能读到真实的目标状态
    assert_key_auth_ready

    restart_and_verify
    print_summary
}

main "$@"
