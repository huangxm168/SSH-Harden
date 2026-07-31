#!/usr/bin/env bash
# 在 Debian 12 容器内测试 ssh-harden.sh
# 复现 VMISS 场景：镜像出厂预置 PubkeyAuthentication no
set -uo pipefail

PASS=0; FAIL=0
ok()   { printf '  \033[1;32m✓\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); }
head_() { printf '\n\033[36m===== %s =====\033[0m\n' "$*"; }

export DEBIAN_FRONTEND=noninteractive
head_ "准备环境"
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq openssh-server iproute2 procps >/dev/null 2>&1
mkdir -p /run/sshd
echo "openssh-server 已安装: $(sshd -V 2>&1 | head -1)"

# ---- 复现 VMISS 镜像：末尾追加商家定制 ----
cat >> /etc/ssh/sshd_config <<'EOF'

PermitRootLogin yes
PasswordAuthentication yes
PubkeyAuthentication no
EOF
cp /etc/ssh/sshd_config /tmp/sshd_config.origin

# ---- mock systemctl ----
cat > /usr/local/bin/systemctl <<'MOCK'
#!/bin/bash
echo "systemctl $*" >> /tmp/systemctl.log
case "$*" in
  "list-unit-files ssh.service") echo "ssh.service enabled"; exit 0 ;;
  "list-unit-files sshd.service") exit 1 ;;
  "cat ssh.service") echo "[Unit]"; exit 0 ;;
  "cat sshd.service") exit 1 ;;
  "is-active --quiet ssh.socket") exit 1 ;;
  "is-active --quiet ssh.service") pgrep -x sshd >/dev/null 2>&1 && exit 0 || exit 1 ;;
  "daemon-reload") exit 0 ;;
  restart*) pkill -x sshd >/dev/null 2>&1; sleep 0.3; /usr/sbin/sshd && exit 0 || exit 1 ;;
  *) exit 0 ;;
esac
MOCK
chmod +x /usr/local/bin/systemctl
hash -r

# 生成测试密钥
ssh-keygen -t ed25519 -f /tmp/testkey -N "" -q

SCRIPT=/work/ssh-harden.sh

#===============================================================================
head_ "测试 1：出厂状态确认（复现 VMISS 场景）"
BEFORE_PK=$(sshd -T 2>/dev/null | awk '$1=="pubkeyauthentication"{print $2}')
[ "$BEFORE_PK" = "no" ] && ok "出厂 pubkeyauthentication=no（VMISS 场景已复现）" \
                        || bad "预期 no，实际 $BEFORE_PK"

#===============================================================================
head_ "测试 2：--dry-run 不产生任何改动"
bash "$SCRIPT" -f /tmp/testkey.pub -p 54278 -d --dry-run -y >/tmp/dryrun.log 2>&1
DRY_RC=$?
[ $DRY_RC -eq 0 ] && ok "dry-run 退出码 0" || { bad "dry-run 退出码 $DRY_RC"; tail -5 /tmp/dryrun.log; }
grep -q "DRY-RUN" /tmp/dryrun.log && ok "输出包含 DRY-RUN 标记" || bad "缺少 DRY-RUN 标记"
diff -q /etc/ssh/sshd_config /tmp/sshd_config.origin >/dev/null \
    && ok "sshd_config 未被改动" || bad "sshd_config 被改动了！"
[ ! -f /etc/ssh/sshd_config.d/10-ssh-harden.conf ] \
    && ok "未创建 drop-in 文件" || bad "dry-run 竟创建了 drop-in 文件！"
[ ! -s /root/.ssh/authorized_keys ] 2>/dev/null \
    && ok "未写入 authorized_keys" || bad "dry-run 竟写入了密钥！"

#===============================================================================
head_ "测试 3：护栏 —— 无密钥时禁用密码应被拒绝"
OUT=$(bash "$SCRIPT" -d -y 2>&1); RC=$?
if [ $RC -ne 0 ]; then
    ok "正确拒绝（退出码 $RC）"
    echo "$OUT" | grep -qE "找不到|没有合法公钥" && ok "给出了明确原因" || bad "原因不明确"
else
    bad "危险！无密钥却允许禁用密码"
fi
# 确认被拒绝后已回滚，配置未残留
CUR_PW=$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')
[ "$CUR_PW" = "yes" ] && ok "密码认证仍为 yes（未被误关）" || bad "密码认证被关成 $CUR_PW！"

#===============================================================================
head_ "测试 4：完整执行（装密钥 + 改端口 + 禁密码）"
bash "$SCRIPT" -f /tmp/testkey.pub -p 54278 -d -y >/tmp/run.log 2>&1
RUN_RC=$?
[ $RUN_RC -eq 0 ] && ok "执行成功" || { bad "执行失败，退出码 $RUN_RC"; tail -20 /tmp/run.log; }

EFF_PORT=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
EFF_PK=$(sshd -T 2>/dev/null   | awk '$1=="pubkeyauthentication"{print $2}')
EFF_PW=$(sshd -T 2>/dev/null   | awk '$1=="passwordauthentication"{print $2}')
EFF_RL=$(sshd -T 2>/dev/null   | awk '$1=="permitrootlogin"{print $2}')

[ "$EFF_PORT" = "54278" ] && ok "端口已生效: 54278" || bad "端口错误: $EFF_PORT"
[ "$EFF_PK" = "yes" ] && ok "★ 密钥认证被自动开启（防锁死核心）" \
                      || bad "★ 密钥认证仍为 $EFF_PK —— 会导致锁死！"
[ "$EFF_PW" = "no" ] && ok "密码认证已禁用" || bad "密码认证未禁用: $EFF_PW"
# sshd -T 把 prohibit-password 规范化输出为 without-password，两者等价
case "$EFF_RL" in
    prohibit-password|without-password) ok "PermitRootLogin 已收紧 ($EFF_RL)" ;;
    *) bad "PermitRootLogin: $EFF_RL" ;;
esac

# 认证方式不能为空集（本次事故的判别标志）
if [ "$EFF_PK" = "yes" ] || [ "$EFF_PW" = "yes" ]; then
    ok "★ 至少有一种认证方式可用（未锁死）"
else
    bad "★★ 严重：所有认证方式全部关闭，已锁死！"
fi

[ -f /etc/ssh/sshd_config.d/10-ssh-harden.conf ] && ok "drop-in 文件已生成" || bad "drop-in 缺失"
grep -q "$(awk '{print $2}' /tmp/testkey.pub)" /root/.ssh/authorized_keys 2>/dev/null \
    && ok "公钥已正确写入" || bad "公钥未写入"
PERM=$(stat -c '%a' /root/.ssh/authorized_keys 2>/dev/null)
[ "$PERM" = "600" ] && ok "authorized_keys 权限 600" || bad "权限错误: $PERM"

#===============================================================================
head_ "测试 5：drop-in 是否真的压过主配置的 PubkeyAuthentication no"
if grep -qE '^\s*PubkeyAuthentication\s+no' /etc/ssh/sshd_config; then
    ok "主配置中的 PubkeyAuthentication no 仍在（未被粗暴改写）"
    [ "$EFF_PK" = "yes" ] && ok "★ 但 drop-in 成功覆盖，生效值为 yes" || bad "drop-in 未生效"
else
    ok "主配置已被回退逻辑修改（drop-in 未生效时的预期路径）"
fi

#===============================================================================
head_ "测试 6：真实密钥登录验证"
pkill -x sshd >/dev/null 2>&1; sleep 0.3; /usr/sbin/sshd
sleep 1
if ss -ltn 2>/dev/null | grep -q ':54278'; then
    ok "sshd 正在 54278 监听"
    LOGIN=$(ssh -p 54278 -i /tmp/testkey -o StrictHostKeyChecking=no \
            -o UserKnownHostsFile=/dev/null -o IdentitiesOnly=yes \
            -o PreferredAuthentications=publickey -o ConnectTimeout=10 \
            root@127.0.0.1 'echo LOGIN_OK' 2>/dev/null)
    [ "$LOGIN" = "LOGIN_OK" ] && ok "★★ 密钥登录成功 —— 端到端验证通过" \
                              || bad "★★ 密钥登录失败（这正是要防止的锁死状态）"
else
    bad "sshd 未在 54278 监听"
fi

#===============================================================================
head_ "测试 7：--rollback 还原"
bash "$SCRIPT" --rollback -y >/tmp/rollback.log 2>&1
RB_RC=$?
[ $RB_RC -eq 0 ] && ok "回滚执行成功" || { bad "回滚失败 $RB_RC"; tail -10 /tmp/rollback.log; }

RB_PORT=$(sshd -T 2>/dev/null | awk '$1=="port"{print $2}')
RB_PW=$(sshd -T 2>/dev/null   | awk '$1=="passwordauthentication"{print $2}')
[ "$RB_PORT" = "22" ] && ok "端口已还原为 22" || bad "端口未还原: $RB_PORT"
[ "$RB_PW" = "yes" ] && ok "密码认证已还原" || bad "密码认证未还原: $RB_PW"
[ ! -f /etc/ssh/sshd_config.d/10-ssh-harden.conf ] \
    && ok "drop-in 文件已清除" || bad "drop-in 文件残留"

#===============================================================================
head_ "测试 8：兼容 getopts 传统写法（组合 / 粘连短选项）"
# 旧命令可能被固化在短链接或运维手册里，形如 -ou <URL> / -p<端口>，必须继续可用
OUT8=$(bash "$SCRIPT" -of /tmp/testkey.pub -p54278 -dn -y 2>&1)
if grep -q '未知选项' <<< "$OUT8"; then
    bad "组合 / 粘连短选项解析失败"
    grep '未知选项' <<< "$OUT8" | head -1
else
    ok "-of（组合）、-p54278（粘连）、-dn（多标志）均被正确解析"
fi
grep -q 'Port 54278' <<< "$OUT8" && ok "粘连值 -p54278 正确解析为 Port 54278" \
                                 || bad "粘连值解析错误"
bash "$SCRIPT" --version >/dev/null 2>&1 && ok "长选项不受展开逻辑影响" \
                                         || bad "长选项被破坏"

#===============================================================================
head_ "测试 9：交互确认的可见性与输入处理"
# 起因：confirm() 曾用 read -r -p "..." reply < /dev/tty 2>/dev/null，
# 而 read -p 的提示恰好也写 stderr，被那个 2>/dev/null 一并吞掉，
# 用户看到的是脚本无声挂起、不知道在等什么，只能瞎按一个键。
# 这些用例守的就是「提示必须真的被打印出来，且说清楚每个选项的后果」。
if ! command -v script >/dev/null 2>&1; then
    printf '  \033[33m-\033[0m 缺少 script 命令（util-linux），跳过交互测试\n'
else
    reset_state() {
        cp /tmp/sshd_config.origin /etc/ssh/sshd_config
        rm -f /etc/ssh/sshd_config.d/10-ssh-harden.conf
        rm -rf /var/backups/ssh-harden
    }
    # confirm 读的是 /dev/tty，管道喂不进去，必须借 script 造一个伪终端
    ask() {
        reset_state
        printf '%b' "$1" | script -qec "bash $SCRIPT -f /tmp/testkey.pub -d" /dev/null 2>&1 \
            | sed -e 's/\x1b\[[0-9;]*m//g' -e 's/\r$//'
    }
    eff_pw() { sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}'; }

    OUT9="$(ask '\n')"
    grep -q '请输入 \[y/n\]' <<< "$OUT9" \
        && ok "★ 确认提示真的被打印出来（守 read -p 提示被 2>/dev/null 吞掉的回归）" \
        || bad "★ 确认提示不可见 —— 用户会看到脚本无声挂起"
    grep -q 'y / yes' <<< "$OUT9" && grep -q 'n / no' <<< "$OUT9" \
        && ok "两个选项及其后果都已列出" || bad "选项说明缺失"
    grep -q '直接回车同此' <<< "$OUT9" \
        && ok "明确告知「直接回车 = 取消」" || bad "未说明回车的含义"
    grep -q '建议：' <<< "$OUT9" \
        && ok "给出了「该怎么做才能满足条件」的建议" || bad "缺少行动建议"
    [ "$(eff_pw)" = "yes" ] \
        && ok "回车＝取消并回滚，密码认证未被误关" || bad "回车后密码认证变成 $(eff_pw)"

    ask 'yes\n' >/dev/null
    [ "$(eff_pw)" = "no" ] && ok "输入 yes 被正确接受（旧实现只认单字符 y）" \
                           || bad "输入 yes 未被接受，密码认证为 $(eff_pw)"

    ask 'n\n' >/dev/null
    [ "$(eff_pw)" = "yes" ] && ok "输入 n 取消并回滚" || bad "输入 n 后密码认证为 $(eff_pw)"

    OUT9R="$(ask 'xyz\ny\n')"
    grep -q '无法识别的输入' <<< "$OUT9R" \
        && ok "无法识别的输入会提示并重新询问" || bad "未提示重新输入"
    [ "$(eff_pw)" = "no" ] && ok "重试后输入 y 正常继续（不再一错就中止）" \
                           || bad "重试失败，密码认证为 $(eff_pw)"

    OUT9B="$(ask 'a\nb\nc\n')"
    grep -q '连续 3 次无法识别输入' <<< "$OUT9B" \
        && ok "连续 3 次无效输入后按取消处理并说明原因" || bad "多次无效输入的处理不明确"
    [ "$(eff_pw)" = "yes" ] && ok "该场景同样完成回滚" || bad "未回滚，密码认证为 $(eff_pw)"

    grep -q '执行计划' <<< "$OUT9" \
        && ok "动手前打印了执行计划预告" || bad "缺少执行计划预告"
    reset_state
fi

#===============================================================================
printf '\n\033[36m===== 结果 =====\033[0m\n'
printf '  通过: \033[1;32m%d\033[0m   失败: \033[31m%d\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && printf '  \033[1;32m全部测试通过\033[0m\n' || printf '  \033[31m存在失败项\033[0m\n'
exit "$FAIL"
