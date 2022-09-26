package conf

type KurumiConfig struct {
	flag_anti_debugger bool
	flag_anti_vm       bool
}

func (c KurumiConfig) AntiDebugger() bool {
	return c.flag_anti_debugger
}

func (c KurumiConfig) AntiVM() bool {
	return c.flag_anti_vm
}

var globalConfig KurumiConfig

func GetConfig() *KurumiConfig {
	return &globalConfig
}
