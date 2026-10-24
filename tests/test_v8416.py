"""v8.4.16：Docker 镜像（Dockerfile、docker/entrypoint.sh、.github/workflows/docker.yml、README「Docker」一节）。
镜像内容复用离线安装包脚本 .github/offline/build.sh（NO_APK / NO_TAR），真正的构建与运行测试在 GitHub Actions 里做
（amd64 / arm64 原生 runner，host 网络实际起容器），这里检查各文件之间的约定不被改坏"""
import os
import re
import subprocess
import unittest

from tests.helper import server

assert server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VER = "8.4.16"


def read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


class VersionTest(unittest.TestCase):
    def test_version(self):
        import sys
        self.assertEqual(sys.modules["shunt.base"].PANEL_VERSION, VER)

    def test_changelog_top(self):
        heads = [ln for ln in read("CHANGELOG.md").splitlines() if ln.startswith("## v")]
        self.assertTrue(heads[0].startswith("## v" + VER), heads[0])

    def test_built(self):
        self.assertIn(f'PANEL_VERSION = "{VER}"', read("server.py"))


class DockerfileTest(unittest.TestCase):
    def setUp(self):
        self.df = read("Dockerfile")

    def test_alpine_matches_offline(self):
        """基础镜像的 Alpine 版本必须是离线包支持的版本之一"""
        m = re.search(r"^ARG ALPINE=(\S+)$", self.df, re.M)
        self.assertTrue(m)
        offline = re.search(r'alpine: \[([^\]]+)\]', read(".github", "workflows", "offline.yml")).group(1)
        self.assertIn(f'"{m.group(1)}"', offline)
        self.assertEqual(self.df.count("FROM alpine:${ALPINE}"), 2)

    def test_reuses_offline_build(self):
        self.assertIn("NO_APK=1 NO_TAR=1 sh /src/.github/offline/build.sh", self.df)
        b = read(".github", "offline", "build.sh")
        self.assertIn('if [ -n "${NO_APK:-}" ]', b)
        self.assertIn('[ -n "${NO_TAR:-}" ] && {', b)
        # NO_TAR 必须在三内核自测之后才退出：自测失败照样让镜像构建失败
        self.assertLess(b.index("自测 mihomo Smart"), b.index("NO_TAR:-"))

    def test_files_and_layout(self):
        for f in ("server.py", "index.html", "tproxy.sh", "selftest.sh", "init.d/shunt", "init.d/shunt-core", "docker/entrypoint.sh"):
            self.assertTrue(os.path.isfile(os.path.join(ROOT, f)), f)
        self.assertIn("cp $W/init.d/shunt $W/init.d/shunt-core $R/etc/init.d/", self.df)
        self.assertIn('VOLUME ["/data"]', self.df)
        for d in ("mihomo", "mihomo-panel", "sing-box"):
            self.assertIn(f"ln -s /data/{d} /etc/{d}", self.df)
        self.assertIn('ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/shunt-entrypoint"]', self.df)
        self.assertNotIn("-g", self.df.split("ENTRYPOINT", 1)[1].split("\n", 1)[0])  # 只把信号交给入口脚本，由它按顺序停
        for k in ('rc_sys="docker"', 'rc_provide="loopback net"', 'rc_controller_cgroups="NO"'):
            self.assertIn(k, self.df)
        self.assertIn("HEALTHCHECK", self.df)

    def test_runtime_deps_match_install(self):
        inst = re.search(r'^PKGS="([^"]+)"', read("install.sh"), re.M).group(1).split()
        apk = self.df.split("RUN apk add --no-cache", 1)[1].split("&&", 1)[0].replace("\\", " ").split()
        for p in inst + ["openrc", "tini", "py3-yaml", "openssl"]:
            self.assertIn(p, apk)

    def test_dockerignore_keeps_build_inputs(self):
        ign = read(".dockerignore").split()
        for keep in (".github", "init.d", "docker", "server.py"):
            self.assertNotIn(keep, ign)
        self.assertIn(".git", ign)

    def test_not_deployed_by_online_update(self):
        """Dockerfile / 入口脚本不是设备上的文件，不进在线更新清单"""
        lst = [x.strip() for x in read("update-files.txt").splitlines() if x.strip() and not x.startswith("#")]
        for x in lst:
            self.assertFalse(x.startswith("docker/") or x in ("Dockerfile", ".dockerignore"), x)


class EntrypointTest(unittest.TestCase):
    def setUp(self):
        self.s = read("docker", "entrypoint.sh")

    def test_syntax(self):
        subprocess.run(["sh", "-n", os.path.join(ROOT, "docker", "entrypoint.sh")], check=True)
        self.assertTrue(os.access(os.path.join(ROOT, "docker", "entrypoint.sh"), os.X_OK))

    def test_openrc_state_reset(self):
        """docker restart 保留容器文件系统：上次的 started / pid 记录必须清掉，否则 rc-service start 报 already started"""
        self.assertIn("rm -rf /run/openrc && mkdir -p /run/openrc/exclusive && touch /run/openrc/softlevel", self.s)
        self.assertIn("rm -f /run/shunt.pid /run/shunt-core.pid /run/shunt-core.prep", self.s)

    def test_start_order_and_manual_stop(self):
        a = self.s.index("rc-service shunt-core start")
        b = self.s.index("rc-service shunt start")
        self.assertLess(a, b)
        self.assertLess(self.s.index("/data/mihomo-panel/core_stopped"), a)
        self.assertLess(self.s.index('tproxy.sh" stop leftovers'), a)  # 先清上次被强杀留下的规则

    def test_shutdown_drops_rules_first(self):
        sd = self.s.split("shutdown() {", 1)[1].split("\n}", 1)[0]
        self.assertLess(sd.index("nft delete table inet mihomo_panel"), sd.index("rc-service shunt stop"))
        self.assertLess(sd.index("rc-service shunt stop"), sd.index("rc-service shunt-core stop"))
        self.assertIn("leftovers", sd)
        self.assertIn("trap shutdown TERM INT QUIT HUP", self.s)
        # 等待用 sleep & wait：信号到来时 wait 立即返回、trap 马上执行（前台 sleep 要等它结束）
        self.assertIn("sleep 10 &\n  wait $!", self.s)

    def test_table_name_matches_tproxy(self):
        self.assertIn("TABLE=mihomo_panel", read("tproxy.sh"))
        self.assertIn("nft delete table inet mihomo_panel", read("init.d", "shunt-core"))

    def test_default_data_same_as_install(self):
        want = """printf '{"secret":"","mode":"rule","tproxy":true,"subs":[],"rules":[]}\\n'"""
        self.assertIn(want, read("install.sh"))
        self.assertIn(want, self.s)

    def test_seed_does_not_overwrite(self):
        self.assertIn('[ -s "/data/mihomo/$f" ] ||', self.s)
        self.assertIn('[ -s "/data/sing-box/rules/${f##*/}" ] ||', self.s)


class WorkflowTest(unittest.TestCase):
    def setUp(self):
        self.w = read(".github", "workflows", "docker.yml")

    def test_targets(self):
        for k in ("linux/amd64", "linux/arm64", "ubuntu-24.04-arm", "registry: ghcr.io", "push-by-digest=true",
                  "packages: write", "workflow_dispatch", "imagetools create"):
            self.assertIn(k, self.w)
        for t in (':latest"', ':hk001"', ':v$VER"'):
            self.assertIn("$IMAGE" + t, self.w)
            self.assertIn("shunt" + t, self.w)

    def test_dockerhub_optional(self):
        self.assertIn("DH_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}", self.w)
        self.assertIn("secrets.DOCKERHUB_USERNAME || 'skycn2022'", self.w)
        self.assertEqual(self.w.count("if: env.DH_TOKEN != ''"), 2)
        self.assertIn("if: env.DH_TOKEN == ''", self.w)

    def test_smoke_test_before_publish(self):
        self.assertIn("needs: [prep, build]", self.w)
        for k in ("--network host", "--cap-add NET_ADMIN", "--device /dev/net/tun", "nft list table inet mihomo_panel",
                  "docker stop shunt", '"action":"restart"'):
            self.assertIn(k, self.w)

    def test_yaml(self):
        try:
            import yaml
        except ImportError:
            self.skipTest("没有 PyYAML")
        d = yaml.safe_load(self.w)
        self.assertEqual(set(d["jobs"]), {"prep", "build", "publish"})
        on = d.get("on", d.get(True))
        self.assertEqual(on["push"]["branches"], ["Hk001"])

    def test_check_workflow_lints_entrypoint(self):
        self.assertIn("docker/entrypoint.sh", read(".github", "workflows", "check.yml"))


class ReadmeTest(unittest.TestCase):
    def test_docker_section(self):
        r = read("README.md")
        self.assertIn("### Docker", r)
        sec = r.split("### Docker", 1)[1].split("\n## ", 1)[0]
        for k in ("network_mode: host", "NET_ADMIN", "NET_RAW", "SYS_MODULE", "/dev/net/tun", "unless-stopped",
                  "nft_tproxy", "net.ipv4.ip_forward=1", "skycn2022/shunt", "ghcr.io/skycnhe/shunt", "DOCKER-USER",
                  "docker run", "stop_grace_period"):
            self.assertIn(k, sec)


if __name__ == "__main__":
    unittest.main()
