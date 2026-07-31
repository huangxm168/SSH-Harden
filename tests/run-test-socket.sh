#!/usr/bin/env bash
# 验证 ssh.socket 激活路径（run-test.sh 覆盖不到的部分）
#
# 与 run-test.sh 的区别：那个跑在普通容器里、systemctl 是 mock 的，
# 因此永远测不到 socket 单元与 service 单元的真实交互。本脚本起一个带真实
# systemd 的特权容器，覆盖三件 mock 环境下无法暴露的事：
#   1. socket 激活模式下改端口是否真的生效（重启顺序错了会被 systemd 拒绝）
#   2. ssh.socket 已启用但当前未监听时，重启后端口会不会被抢回去
#   3. sshd 特权分离目录 /run/sshd 缺失时脚本能否自愈
#
# 用法: bash tests/run-test-socket.sh [镜像]     默认 debian:13
# 需要 docker 且允许 --privileged。
set -uo pipefail

IMAGE="${1:-debian:13}"
CONTAINER="ssh-harden-socket-test"
PORT=54278
# 容器内的工作文件一律放 /root：/tmp 会被 systemd 在重启时清空，
# 而本测试要跨容器重启复用同一把测试密钥
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()    { printf '  \033[1;32m✓\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()   { printf '  \033[31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
head_() { printf '\n\033[36m===== %s =====\033[0m\n' "$*"; }
dex()   { docker exec "$CONTAINER" bash -c "$1"; }

# 匹配容器内命令的输出。绝不能写成 dex '...' | grep：本脚本启用了 pipefail，
# 而被测命令失败是常态（如 /run/sshd 缺失时 sshd -t 返回 255），
# 管道会把它判定为整体失败，断言结果与事实相反。先取输出、再匹配。
dex_has() {
    local out
    out="$(docker exec "$CONTAINER" bash -c "$1" 2>&1 || true)"
    grep -qE "$2" <<< "$out"
}

cleanup() { docker rm -f "$CONTAINER" >/dev/null 2>&1; }
trap cleanup EXIT

#===============================================================================
head_ "准备带 systemd 的 ${IMAGE} 容器"
cleanup
docker build -q -t ssh-harden-systemd-test - >/dev/null <<EOF || { echo "镜像构建失败"; exit 1; }
FROM ${IMAGE}
ENV DEBIAN_FRONTEND=noninteractive container=docker
RUN apt-get update -qq && apt-get install -y -qq systemd systemd-sysv openssh-server iproute2 procps >/dev/null
RUN rm -f /lib/systemd/system/multi-user.target.wants/* /etc/systemd/system/*.wants/* \
          /lib/systemd/system/local-fs.target.wants/* /lib/systemd/system/sockets.target.wants/*udev* \
          /lib/systemd/system/basic.target.wants/* || true
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF

docker run -d --name "$CONTAINER" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    -v "${REPO_DIR}:/work:ro" ssh-harden-systemd-test >/dev/null || { echo "容器启动失败"; exit 1; }

for _ in $(seq 1 30); do
    dex_has 'systemctl is-system-running' 'running|degraded' && break
    sleep 1
done
SSHD_VER="$(docker exec "$CONTAINER" bash -c 'sshd -V 2>&1' | head -1 || true)"
dex_has 'systemctl is-system-running' 'running|degraded' \
    && ok "systemd 已就绪（${SSHD_VER}）" \
    || { bad "systemd 未能启动，无法继续"; exit 1; }

dex 'ssh-keygen -t ed25519 -f /root/testkey -N "" -q' >/dev/null 2>&1

# 切换为 socket 激活模式（Ubuntu 22.10+ 的默认形态）
dex '
systemctl stop ssh.service >/dev/null 2>&1
systemctl disable ssh.service >/dev/null 2>&1
systemctl enable --now ssh.socket >/dev/null 2>&1
' >/dev/null 2>&1

#===============================================================================
head_ "测试 1：socket 激活模式已就位"
dex_has 'systemctl is-active ssh.socket' '^active' \
    && ok "ssh.socket 处于监听状态" || bad "ssh.socket 未激活"
dex "ss -ltnp | grep -q ':22 .*systemd'" \
    && ok "22 端口由 systemd 持有（而非 sshd 自己 bind）" || bad "22 端口未由 systemd 持有"

#===============================================================================
head_ "测试 2：/run/sshd 缺失时脚本能自愈"
# socket 激活下 ssh.service 不常驻，systemd 会回收 RuntimeDirectory，
# 此时 sshd -t / -T 一律以 255 退出，旧版脚本会在备份阶段直接崩掉
dex_has 'rm -rf /run/sshd; sshd -t' 'Missing privilege separation' \
    && ok "已复现 sshd -t 因 /run/sshd 缺失而失败" || bad "未能复现 /run/sshd 缺失场景"

OUT2=$(dex 'bash /work/ssh-harden.sh --version 2>&1'); RC2=$?
[ $RC2 -eq 0 ] && ok "脚本仍可正常启动" || bad "脚本启动失败: $OUT2"

dex 'rm -rf /run/sshd; bash /work/ssh-harden.sh -f /root/testkey.pub -n -y >/root/dry.log 2>&1'
dex '[ -d /run/sshd ]' \
    && ok "脚本自动补建了 /run/sshd" || bad "/run/sshd 未被补建"
dex 'grep -q "Missing privilege separation" /root/dry.log' \
    && bad "仍出现特权分离目录报错" || ok "预演全程无特权分离目录报错"

#===============================================================================
head_ "测试 3：socket 激活模式下改端口 + 装密钥 + 禁密码"
dex "bash /work/ssh-harden.sh -f /root/testkey.pub -p ${PORT} -d -y >/root/run.log 2>&1"
RC3=$?
[ $RC3 -eq 0 ] && ok "脚本执行成功" || { bad "脚本执行失败（退出码 $RC3）"; dex 'tail -20 /root/run.log'; }

dex 'grep -q "already active, refusing" /root/run.log' \
    && bad "★ 命中 systemd 拒绝 socket 监听的老问题" \
    || ok "★ 未出现 Socket service already active 的拒绝"

dex "ss -ltn | grep -q ':${PORT}'" \
    && ok "★ 新端口 ${PORT} 已在监听" || bad "★ 新端口 ${PORT} 未监听（改端口未生效）"
dex "ss -ltn | grep -qE ':22[[:space:]]'" \
    && bad "旧端口 22 仍在监听" || ok "旧端口 22 已停止监听"

dex "[ -f /etc/systemd/system/ssh.socket.d/10-ssh-harden.conf ]" \
    && ok "socket drop-in 已写入" || bad "socket drop-in 缺失"
dex "grep -q 'ListenStream=${PORT}' /etc/systemd/system/ssh.socket.d/10-ssh-harden.conf" \
    && ok "socket 单元端口已改为 ${PORT}" || bad "socket 单元端口未改"

EFF_PK=$(dex 'sshd -T 2>/dev/null | awk "\$1==\"pubkeyauthentication\"{print \$2}"')
EFF_PW=$(dex 'sshd -T 2>/dev/null | awk "\$1==\"passwordauthentication\"{print \$2}"')
[ "$EFF_PK" = "yes" ] && ok "密钥认证已启用" || bad "密钥认证为 $EFF_PK"
[ "$EFF_PW" = "no" ]  && ok "密码认证已禁用" || bad "密码认证为 $EFF_PW"

#===============================================================================
head_ "测试 4：经 socket 激活的真实密钥登录"
LOGIN=$(dex "ssh -p ${PORT} -i /root/testkey -o StrictHostKeyChecking=no \
    -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
    -o PreferredAuthentications=publickey -o ConnectTimeout=10 \
    root@127.0.0.1 'echo LOGIN_OK' 2>/dev/null")
[ "$LOGIN" = "LOGIN_OK" ] && ok "★★ 密钥登录成功 —— socket 激活路径端到端可用" \
                          || bad "★★ 密钥登录失败"

#===============================================================================
head_ "测试 5：重启后端口保持（socket 激活模式）"
docker restart "$CONTAINER" >/dev/null 2>&1
sleep 8
dex "ss -ltn | grep -q ':${PORT}'" \
    && ok "★ 重启后仍监听 ${PORT}" || { bad "★ 重启后端口丢失"; dex 'ss -ltn | head -5'; }

#===============================================================================
head_ "测试 6：--rollback 还原（socket 模式下的重启顺序）"
dex 'bash /work/ssh-harden.sh --rollback -y >/root/rb.log 2>&1'
RC6=$?
[ $RC6 -eq 0 ] && ok "回滚执行成功" || { bad "回滚失败（退出码 $RC6）"; dex 'tail -10 /root/rb.log'; }
sleep 1
dex "ss -ltn | grep -qE ':22[[:space:]]'" \
    && ok "端口已还原为 22" || { bad "端口未还原"; dex 'ss -ltn | head -5'; }
dex '[ ! -f /etc/systemd/system/ssh.socket.d/10-ssh-harden.conf ]' \
    && ok "socket drop-in 已清除" || bad "socket drop-in 残留"
dex_has 'systemctl is-active ssh.socket' '^active' \
    && ok "ssh.socket 仍处于监听状态（激活形态未被破坏）" || bad "ssh.socket 未恢复监听"

#===============================================================================
head_ "测试 7：ssh.socket 已启用但未监听 —— 拆除重启后端口回退的定时炸弹"
# 这是最隐蔽的一种：当前由 ssh.service 监听，脚本若只看 is-active 会误判为传统模式，
# 改完端口当场一切正常，重启后 ssh.socket 把端口抢回默认值，配合防火墙即失联
dex '
systemctl stop ssh.socket >/dev/null 2>&1
systemctl enable ssh.socket >/dev/null 2>&1
systemctl enable ssh.service >/dev/null 2>&1
systemctl start ssh.service >/dev/null 2>&1
' >/dev/null 2>&1
sleep 1
SOCK_EN=$(dex 'systemctl is-enabled ssh.socket 2>/dev/null')
SOCK_AC=$(dex 'systemctl is-active ssh.socket 2>/dev/null')
if [ "$SOCK_EN" = "enabled" ] && [ "$SOCK_AC" != "active" ]; then
    ok "场景已就位（ssh.socket enabled 但 inactive）"
else
    # Ubuntu 的单元依赖会在 start ssh.service 时把 ssh.socket 一并拉起，
    # 这个中间态在该发行版上根本不存在，跳过而非记为失败
    printf '  \033[33m-\033[0m 本发行版无法构造该场景（enabled=%s active=%s），跳过测试 7\n' \
        "$SOCK_EN" "$SOCK_AC"
    printf '\n\033[36m===== 结果（%s）=====\033[0m\n' "$IMAGE"
    printf '  通过: \033[1;32m%d\033[0m   失败: \033[31m%d\033[0m   跳过: 1 组\n' "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ] && printf '  \033[1;32m全部测试通过\033[0m\n' || printf '  \033[31m存在失败项\033[0m\n'
    exit "$FAIL"
fi

dex "bash /work/ssh-harden.sh -f /root/testkey.pub -p ${PORT} -y >/root/run7.log 2>&1"
RC7=$?
[ $RC7 -eq 0 ] && ok "脚本执行成功" || { bad "脚本执行失败（退出码 $RC7）"; dex 'tail -20 /root/run7.log'; }
dex 'grep -q "重启后它会接管端口" /root/run7.log' \
    && ok "脚本识别出 ssh.socket 会在重启后接管" || bad "脚本未给出接管提示"
dex "[ -f /etc/systemd/system/ssh.socket.d/10-ssh-harden.conf ]" \
    && ok "★ 即使 socket 未监听也同步写入了 socket drop-in" \
    || bad "★ 未写入 socket drop-in —— 重启后端口会回退"
dex "ss -ltn | grep -q ':${PORT}'" && ok "当前已监听 ${PORT}" || bad "当前未监听 ${PORT}"

docker restart "$CONTAINER" >/dev/null 2>&1
sleep 8
dex "ss -ltn | grep -q ':${PORT}'" \
    && ok "★★ 重启后端口仍是 ${PORT} —— 定时炸弹已拆除" \
    || { bad "★★ 重启后端口回退，仍会失联"; dex 'ss -ltn | head -5'; }
dex "ss -ltn | grep -qE ':22[[:space:]]'" \
    && bad "重启后 22 端口被重新占用" || ok "重启后 22 端口未被占用"

#===============================================================================
printf '\n\033[36m===== 结果（%s）=====\033[0m\n' "$IMAGE"
printf '  通过: \033[1;32m%d\033[0m   失败: \033[31m%d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && printf '  \033[1;32m全部测试通过\033[0m\n' || printf '  \033[31m存在失败项\033[0m\n'
exit "$FAIL"
