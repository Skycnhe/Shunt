package webapi

// RegisterRoutes 注册全部 API 路由（handlers_*.go 中实现，按功能拆分）。
func RegisterRoutes() {
	registerStateRoutes()
	registerGroupRoutes()
	registerNodeRoutes()
	registerRuleRoutes()
	registerSystemRoutes()
	registerServiceRoutes()
	registerMiscRoutes()
}
