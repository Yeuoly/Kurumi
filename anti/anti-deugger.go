package anti

type AntiDeugger interface {
	Code() string
}

type DefaultAntiDeugger struct {
	AntiDeugger
}

func (c DefaultAntiDeugger) Code() string {
	return ""
}

func ListAntiDebuggers() []string {
	return []string{"kurumi-anti-debugger-1"}
}
