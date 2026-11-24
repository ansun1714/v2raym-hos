package main

/*
#include <stdint.h>
#include <stdlib.h>
typedef void (*ncore_log_cb)(int level, const char *msg);
static void ncore_invoke_log(ncore_log_cb cb, int level, const char *msg) { if (cb) cb(level, msg); }
typedef int (*ncore_protect_cb)(int fd);
static int ncore_invoke_protect(ncore_protect_cb cb, int fd) { if (cb == NULL) return -1; return cb(fd); }
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/metacubex/mihomo/adapter"
	"github.com/metacubex/mihomo/adapter/outbound"
	"github.com/metacubex/mihomo/common/utils"
	"github.com/metacubex/mihomo/component/dialer"
	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/tunnel"
	"github.com/metacubex/mihomo/tunnel/statistic"
)

var (
	mu        sync.Mutex
	homeSet   bool
	running   bool
	logCb     C.ncore_log_cb
	protectCb C.ncore_protect_cb
)

// ncore_set_protect_cb 注册 socket 保护回调（鸿蒙 VpnConnection.protect）。
// 只有在 VPN 模式下才需要：否则内核自己发出的出站连接会被 TUN 再次拦截造成回环。
//
//export ncore_set_protect_cb
func ncore_set_protect_cb(cb C.ncore_protect_cb) {
	protectCb = cb
	if cb == nil {
		dialer.DefaultSocketHook = nil
		return
	}
	dialer.DefaultSocketHook = func(network, address string, conn syscall.RawConn) error {
		var controlErr error
		protectFailed := false
		err := conn.Control(func(fd uintptr) {
			if protectCb == nil {
				protectFailed = true
				return
			}
			if C.ncore_invoke_protect(protectCb, C.int(fd)) != 1 {
				protectFailed = true
			}
		})
		if err != nil {
			controlErr = err
		}
		if controlErr != nil {
			return controlErr
		}
		if protectFailed {
			return fmt.Errorf("protect socket failed: %s %s", network, address)
		}
		return nil
	}
}


// ncore_version 返回内核版本号，供 UI 显示。
//
//export ncore_version
func ncore_version() *C.char {
	return C.CString(constant.Version)
}

// ncore_set_log_cb 注册内核日志回调，ArkTS 侧转进 hilog。
//
//export ncore_set_log_cb
func ncore_set_log_cb(cb C.ncore_log_cb) {
	logCb = cb
	sub := log.Subscribe()
	go func() {
		for ev := range sub {
			// log.Subscribe 的订阅者不受 YAML 里 log-level 影响：INFO 里带每条连接的目的地址，
			// 先在这里按 WARNING 过滤，作为 NAPI 侧过滤之外的第二道防线。
			if ev.LogLevel < log.WARNING {
				continue
			}
			cmsg := C.CString(ev.Payload)
			if logCb != nil {
				C.ncore_invoke_log(logCb, C.int(ev.LogLevel), cmsg)
			}
			C.free(unsafe.Pointer(cmsg))
		}
	}()
}

// ncore_start 用 YAML 配置启动内核；tun 的 file-descriptor 由 ArkTS 侧注入。
// 返回 NULL 表示成功，否则返回错误字符串（调用方负责 free）。
//
//export ncore_start
func ncore_start(cfgYaml *C.char, homeDir *C.char) *C.char {
	mu.Lock()
	defer mu.Unlock()

	home := C.GoString(homeDir)
	if !homeSet && home != "" {
		constant.SetHomeDir(home)
		homeSet = true
	}

	raw := C.GoString(cfgYaml)
	cfg, err := config.Parse([]byte(raw))
	if err != nil {
		return C.CString("config parse: " + err.Error())
	}
	executor.ApplyConfig(cfg, true)
	running = true
	return nil
}

// ncore_stop 停止内核（关闭监听、释放 tun）。
//
//export ncore_stop
func ncore_stop() {
	mu.Lock()
	defer mu.Unlock()
	if !running {
		return
	}
	executor.Shutdown()
	running = false
}

// ncore_is_running 查询运行状态。
//
//export ncore_is_running
func ncore_is_running() C.int {
	mu.Lock()
	defer mu.Unlock()
	if running {
		return 1
	}
	return 0
}

// ncore_stats 返回实时/累计流量 JSON。
//
//export ncore_stats
func ncore_stats() *C.char {
	up, down := statistic.DefaultManager.Now()
	totalUp, totalDown := statistic.DefaultManager.Total()
	body := map[string]int64{
		"up":        up,
		"down":      down,
		"totalUp":   totalUp,
		"totalDown": totalDown,
	}
	data, err := json.Marshal(body)
	if err != nil {
		return C.CString("{}")
	}
	return C.CString(string(data))
}

// ncore_proxydelay 让内核真实经指定节点请求一次 url，返回 {"delay":毫秒} 或 {"error":"原因"}。
// 界面进程与 VPN 扩展进程不在同一网络命名空间，访问不到 9090 的 REST API，
// 所以测速必须由内进程完成。
//
//export ncore_proxydelay
func ncore_proxydelay(name *C.char, url *C.char, timeoutMs C.int) *C.char {
	return C.CString(proxyDelayJSON(C.GoString(name), C.GoString(url), int(timeoutMs)))
}

func proxyDelayJSON(proxyName string, urlStr string, timeout int) string {
	if urlStr == "" {
		urlStr = "http://www.gstatic.com/generate_204"
	}
	if timeout <= 0 {
		timeout = 5000
	}
	proxy, ok := tunnel.Proxies()[proxyName]
	if !ok {
		return `{"error":"node not found"}`
	}
	expected, _ := utils.NewUnsignedRanges[uint16]("")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	delay, err := proxy.URLTest(ctx, urlStr, expected)
	if err != nil {
		data, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(data)
	}
	if delay == 0 {
		return `{"error":"delay test returned 0"}`
	}
	data, _ := json.Marshal(map[string]uint16{"delay": delay})
	return string(data)
}

// ncore_proxydelay_async 异步测速：立刻返回，结果写进 resPath（含 seq 回显）。
// 必须异步：测速期间内核要回调 JS 执行 socket protect，JS 线程被同步调用占住会直接失败。
//
//export ncore_proxydelay_async
func ncore_proxydelay_async(name *C.char, url *C.char, timeoutMs C.int, resPath *C.char, seq C.int) {
	proxyName := C.GoString(name)
	urlStr := C.GoString(url)
	path := C.GoString(resPath)
	seqNum := int64(seq)
	go func() {
		body := proxyDelayJSON(proxyName, urlStr, int(timeoutMs))
		out := `{"seq":` + strconv.FormatInt(seqNum, 10) + `,` + strings.TrimPrefix(body, "{")
		_ = os.WriteFile(path, []byte(out), 0600)
	}()
}

// ncore_probe_reality_auto 用两种 REALITY 握手方式同时探测同一个 vless+REALITY 出站：
// 经典 X25519（mihomo 默认）与 X25519MLKEM768（新版 Xray 服务端）。
//
// 为什么需要：新版 Xray 的 REALITY 服务端只认 MLKEM 密钥份额，而 mihomo 默认会把
// MLKEM 从 ClientHello 里摘掉（为了兼容老服务端）。服务端判非法后会 fallback 到
// 真实站点的证书，客户端侧表现为 "REALITY authentication failed"——同一节点换
// Xray 内核（v2rayNG）却是通的。两种模式各试一次即可自动分辨，不必让用户手改。
//
// 返回 {"mode":0|1,"delay":毫秒}，两种都不通时返回 {"error":"原因"}。
//
//export ncore_probe_reality_auto
func ncore_probe_reality_auto(nodeJSON *C.char, url *C.char, timeoutMs C.int) *C.char {
	return C.CString(probeRealityAutoJSON(C.GoString(nodeJSON), C.GoString(url), int(timeoutMs)))
}

type realityProbeReq struct {
	Server      string `json:"server"`
	Port        int    `json:"port"`
	UUID        string `json:"uuid"`
	Flow        string `json:"flow"`
	SNI         string `json:"sni"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"pbk"`
	ShortID     string `json:"sid"`
}

type realityProbeResult struct {
	mode  int
	delay uint16
	err   error
}

func probeRealityAutoJSON(reqJSON, urlStr string, timeout int) string {
	var req realityProbeReq
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return jsonError("bad request: " + err.Error())
	}
	if req.Server == "" || req.Port <= 0 || req.UUID == "" || req.PublicKey == "" {
		return jsonError("node fields incomplete")
	}
	if urlStr == "" {
		urlStr = "http://www.gstatic.com/generate_204"
	}
	if timeout <= 0 {
		timeout = 4000
	}
	ch := make(chan realityProbeResult, 2)
	for _, m := range []int{0, 1} {
		mode := m
		go func() {
			delay, err := probeRealityOnce(req, mode, urlStr, timeout)
			ch <- realityProbeResult{mode: mode, delay: delay, err: err}
		}()
	}
	var lastErr error
	for i := 0; i < 2; i++ {
		r := <-ch
		if r.err == nil {
			data, _ := json.Marshal(map[string]int{"mode": r.mode, "delay": int(r.delay)})
			return string(data)
		}
		lastErr = r.err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("probe failed")
	}
	return jsonError(lastErr.Error())
}

func probeRealityOnce(req realityProbeReq, mode int, urlStr string, timeout int) (uint16, error) {
	option := outbound.VlessOption{
		Name:              "reality-probe",
		Server:            req.Server,
		Port:              req.Port,
		UUID:              req.UUID,
		Flow:              req.Flow,
		TLS:               true,
		Network:           "tcp",
		ServerName:        req.SNI,
		ClientFingerprint: req.Fingerprint,
		RealityOpts: outbound.RealityOptions{
			PublicKey:             req.PublicKey,
			ShortID:               req.ShortID,
			SupportX25519MLKEM768: mode == 1,
		},
	}
	proxy, err := outbound.NewVless(option)
	if err != nil {
		return 0, err
	}
	expected, _ := utils.NewUnsignedRanges[uint16]("")
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
	defer cancel()
	delay, err := adapter.NewProxy(proxy).URLTest(ctx, urlStr, expected)
	if err != nil {
		return 0, err
	}
	if delay == 0 {
		return 0, fmt.Errorf("delay test returned 0")
	}
	return delay, nil
}

func jsonError(message string) string {
	data, _ := json.Marshal(map[string]string{"error": message})
	return string(data)
}

// ncore_free 释放本库返回的 C 字符串。
//export ncore_free
func ncore_free(p *C.char) {
	if p != nil {
		C.free(unsafe.Pointer(p))
	}
}

func main() {}
