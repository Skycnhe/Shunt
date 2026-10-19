package webapi

// 对应 Python shunt/webapi.py：/api/subs/update、/api/subs、/api/nodes。

import (
	"fmt"
	"regexp"
	"strings"

	"shunt/internal/base"
	"shunt/internal/core"
	"shunt/internal/data"
	"shunt/internal/links"
	"shunt/internal/schedule"
	"shunt/internal/singbox"
	"shunt/internal/validate"
)

func registerNodeRoutes() {
	Route("POST", "/api/subs/update", apiSubsUpdatePost)
	Route("POST", "/api/subs", apiSubsPost)
	Route("DELETE", "/api/subs", apiSubsDelete)
	Route("POST", "/api/nodes", apiNodesPost)
	Route("DELETE", "/api/nodes", apiNodesDelete)
}

// ---------- POST /api/subs/update ----------

func apiSubsUpdatePost(c *Ctx) (int, any) {
	name := c.BodyStr("name")
	d := data.Load()
	sb := singbox.ActiveCore(d) == "singbox"
	var names []string
	if name != "" {
		names = []string{name}
	}
	okl, bad, msg2 := schedule.SubsUpdate(names, d, "")
	var msg string
	if len(bad) > 0 {
		msg = "更新失败：" + strings.Join(bad, "；")
	} else if sb {
		msg = "已更新：" + strings.Join(okl, "；")
	} else {
		msg = "已更新"
	}
	if msg2 != "" && !strings.Contains(msg2, "无变化") {
		msg += "；" + msg2
	}
	return c.Reply(len(bad) == 0, msg)
}

// ---------- POST /api/subs ----------

func subByName(d map[string]any, name string) map[string]any {
	for _, s := range data.List(d, "subs") {
		if sm, ok := s.(map[string]any); ok && data.Str(sm, "name") == name {
			return sm
		}
	}
	return nil
}

func apiSubsPost(c *Ctx) (int, any) {
	name := strings.TrimSpace(c.BodyStr("name"))
	url := strings.TrimSpace(c.BodyStr("url"))
	d := data.Load()
	if cur := subByName(d, name); cur != nil {
		// 编辑订阅时表单里是打码后的 URL：没改就沿用原链接
		url = unmask(url, data.Str(cur, "url"), maskURL)
	}
	if name == "" || !strings.HasPrefix(url, "http") {
		return c.Send(400, map[string]any{"message": "名称或订阅链接无效"})
	}
	others := []string{}
	for _, s := range data.List(d, "subs") {
		if sm, ok := s.(map[string]any); ok {
			others = append(others, data.Str(sm, "name"))
		}
	}
	if other := validate.SubNameClash(name, others); other != "" {
		return c.Send(400, map[string]any{"message": fmt.Sprintf("与已有订阅「%s」只差符号，会共用同一个缓存文件，请改个名字", other)})
	}
	flt := strings.TrimSpace(c.BodyStr("filter"))
	exc := base.DefaultExclude
	if v, ok := c.Body["exclude"]; ok {
		if s, ok := v.(string); ok {
			exc = strings.TrimSpace(s)
		} else {
			exc = ""
		}
	}
	for _, pat := range []string{flt, exc} {
		if _, err := regexp.Compile(pat); err != nil {
			return c.Send(400, map[string]any{"message": fmt.Sprintf("正则表达式无效：%s（%s）", pat, err)})
		}
	}
	entry := map[string]any{"name": name, "url": url, "filter": flt, "exclude": exc}
	fn := func(dd map[string]any) {
		kept := []any{}
		for _, s := range data.List(dd, "subs") {
			if sm, ok := s.(map[string]any); ok && data.Str(sm, "name") == name {
				continue
			}
			kept = append(kept, s)
		}
		dd["subs"] = append(kept, entry)
	}
	prev := data.Update(fn)
	dd := data.Load()
	if singbox.ActiveCore(dd) == "singbox" { // 先由面板下载节点，再生成配置
		okl, bad := singbox.SbUpdateSubs([]string{name}, dd)
		ok, msg := core.ReloadCore(prev)
		if ok && len(bad) > 0 {
			ok, msg = false, "订阅已保存，但下载失败："+strings.Join(bad, "；")
		}
		if !ok {
			return c.Reply(false, msg)
		}
		return c.Reply(true, "已添加："+strings.Join(okl, "；"))
	}
	ok, msg := core.ReloadCore(prev)
	if ok {
		core.RefreshAfterSub(name, 90) // 订阅下载完成后按实际节点生成地区 / 均衡分组
	}
	return c.Reply(ok, msg)
}

// ---------- DELETE /api/subs ----------

func apiSubsDelete(c *Ctx) (int, any) {
	name := c.BodyStr("name")
	prev := data.Update(func(d map[string]any) {
		kept := []any{}
		for _, s := range data.List(d, "subs") {
			if sm, ok := s.(map[string]any); ok && data.Str(sm, "name") == name {
				continue
			}
			kept = append(kept, s)
		}
		d["subs"] = kept
	})
	return c.Reply(core.ReloadCore(prev))
}

// ---------- POST /api/nodes ----------

func apiNodesPost(c *Ctx) (int, any) {
	d := data.Load()
	existing := []map[string]any{}
	for _, n := range data.List(d, "nodes") {
		if nm, ok := n.(map[string]any); ok {
			existing = append(existing, nm)
		}
	}
	added, errs := links.AddLinks(c.BodyStr("links"), existing, d)
	if len(added) == 0 {
		msg := "没有可导入的节点"
		if len(errs) > 0 {
			msg += "：\n" + strings.Join(errs, "\n")
		}
		return c.Send(400, map[string]any{"message": msg})
	}
	prev := data.Update(func(dd map[string]any) {
		lst := data.List(dd, "nodes")
		for _, a := range added {
			lst = append(lst, a)
		}
		dd["nodes"] = lst
	})
	ok, msg := core.ReloadCore(prev)
	if ok {
		msg = fmt.Sprintf("已导入 %d 个节点", len(added))
	}
	if len(errs) > 0 {
		msg += "；忽略：" + strings.Join(errs, "；")
	}
	return c.Reply(ok, msg)
}

// ---------- DELETE /api/nodes ----------

func apiNodesDelete(c *Ctx) (int, any) {
	names := map[string]bool{}
	if l := c.BodyList("names"); len(l) > 0 {
		for _, x := range l {
			if s, ok := x.(string); ok && s != "" {
				names[s] = true
			}
		}
	} else if s := c.BodyStr("name"); s != "" {
		names[s] = true
	}
	prev := data.Update(func(d map[string]any) {
		kept := []any{}
		for _, n := range data.List(d, "nodes") {
			pname := ""
			if nm, ok := n.(map[string]any); ok {
				pname = data.Str(data.Map(nm, "proxy"), "name")
			}
			if names[pname] {
				continue
			}
			kept = append(kept, n)
		}
		d["nodes"] = kept
	})
	return c.Reply(core.ReloadCore(prev))
}
