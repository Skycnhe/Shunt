"""测试公共部分：用临时目录当数据目录，离线模式导入 server"""
import json, os, sys, tempfile

TMP = tempfile.mkdtemp(prefix="shunt-test-")
os.environ.update(PANEL_OFFLINE="1", PANEL_DATA=os.path.join(TMP, "data.json"), MIHOMO_DIR=TMP, SB_DIR=os.path.join(TMP, "sb"))
with open(os.environ["PANEL_DATA"], "w") as f:
    json.dump({}, f)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server  # noqa: E402  供各测试 from tests.helper import server

__all__ = ["server", "TMP"]
