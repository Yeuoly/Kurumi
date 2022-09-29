package anti

type KurumiAntiDebuggerV1 struct {
	AntiDeugger
}

func (c KurumiAntiDebuggerV1) Code() string {
	return `
//read tracer info from /proc/pid/status
int status_fd = open("/proc/self/status", O_RDONLY);
if (status_fd == -1) {
	exit(0);
}
char status_buf[1024] = { 0 };
read(status_fd, status_buf, 1024);
close(status_fd);
//check tracer info
if (strstr(status_buf, "TracerPid:\t0") == NULL) {
	exit(0);
}
	`
}
