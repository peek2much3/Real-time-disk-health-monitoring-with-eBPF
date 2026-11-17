.PHONY: all generate build install clean

all: build

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

generate: bpf/vmlinux.h
	go generate ./...

build: generate
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o diskhealth .

install: build
	install -m 0755 diskhealth /usr/local/bin/diskhealth
	install -m 0644 diskhealth.service /etc/systemd/system/diskhealth.service
	systemctl daemon-reload

clean:
	rm -f diskhealth diskhealth_*.go diskhealth_*.o bpf/vmlinux.h
