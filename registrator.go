package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"time"

	dockerapi "github.com/fsouza/go-dockerclient"
	"github.com/gliderlabs/pkg/usage"
	"github.com/gliderlabs/registrator/bridge"
)

var Version string

var versionChecker = usage.NewChecker("registrator", Version)

//命令行参数的收集处理
var hostIp = flag.String("ip", "", "IP for ports mapped to the host")
var internal = flag.Bool("internal", false, "Use internal ports instead of published ones")
var explicit = flag.Bool("explicit", false, "Only register containers which have SERVICE_NAME label set")
var useIpFromLabel = flag.String("useIpFromLabel", "", "Use IP which is stored in a label assigned to the container")
var refreshInterval = flag.Int("ttl-refresh", 0, "Frequency with which service TTLs are refreshed")
var refreshTtl = flag.Int("ttl", 0, "TTL for services (default is no expiry)")
var forceTags = flag.String("tags", "", "Append tags for all registered services")
var resyncInterval = flag.Int("resync", 0, "Frequency with which services are resynchronized")
var deregister = flag.String("deregister", "always", "Deregister exited services \"always\" or \"on-success\"")
var retryAttempts = flag.Int("retry-attempts", 0, "Max retry attempts to establish a connection with the backend. Use -1 for infinite retries")
var retryInterval = flag.Int("retry-interval", 2000, "Interval (in millisecond) between retry-attempts.")
var cleanup = flag.Bool("cleanup", false, "Remove dangling services")

func getopt(name, def string) string {
	if env := os.Getenv(name); env != "" {
		return env
	}
	return def
}

//使用此方法来避免到处写err判断
func assert(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	//仅打印版本信息
	if len(os.Args) == 2 && os.Args[1] == "--version" {
		versionChecker.PrintVersion()
		os.Exit(0)
	}
	log.Printf("Starting registrator %s ...", Version)

	//定义命令行解析出错时自动调用的方法
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s [options] <registry URI>\n\n", os.Args[0])
		flag.PrintDefaults()
	}

	//解析命令行参数
	flag.Parse()

	//存在无法解析的命令行参数时，打印的信息
	if flag.NArg() != 1 {
		if flag.NArg() == 0 {
			fmt.Fprint(os.Stderr, "Missing required argument for registry URI.\n\n")
		} else {
			fmt.Fprintln(os.Stderr, "Extra unparsed arguments:")
			fmt.Fprintln(os.Stderr, " ", strings.Join(flag.Args()[1:], " "))
			fmt.Fprint(os.Stderr, "Options should come before the registry URI argument.\n\n")
		}
		flag.Usage()
		os.Exit(2)
	}

	if *hostIp != "" {
		log.Println("Forcing host IP to", *hostIp)
	}

	//对输入的命令行参数的逻辑关系进行判断
	if (*refreshTtl == 0 && *refreshInterval > 0) || (*refreshTtl > 0 && *refreshInterval == 0) {
		assert(errors.New("-ttl and -ttl-refresh must be specified together or not at all"))
	} else if *refreshTtl > 0 && *refreshTtl <= *refreshInterval {
		assert(errors.New("-ttl must be greater than -ttl-refresh"))
	}

	if *retryInterval <= 0 {
		assert(errors.New("-retry-interval must be greater than 0"))
	}

	//指定本地docker的连接方式，需要一个sock
	dockerHost := os.Getenv("DOCKER_HOST")
	if dockerHost == "" {
		if runtime.GOOS != "windows" {
			os.Setenv("DOCKER_HOST", "unix:///tmp/docker.sock")
		} else {
			os.Setenv("DOCKER_HOST", "npipe:////./pipe/docker_engine")
		}
	}

	//通过环境变量创建一个到本地docker的客户端连接，使用的是dockerapi
	//文档 https://docs.docker.com/engine/api/latest/
	docker, err := dockerapi.NewClientFromEnv()
	assert(err)

	if *deregister != "always" && *deregister != "on-success" {
		assert(errors.New("-deregister must be \"always\" or \"on-success\""))
	}

	//Bridge对象能够与本地docker、storage server端交互，并用于保存容器信息
	//根据该项目的文档，flag.Arg(0)表示的就是后端存储的URL
	b, err := bridge.New(docker, flag.Arg(0), bridge.Config{
		HostIp:          *hostIp,
		Internal:        *internal,
		Explicit:        *explicit,
		UseIpFromLabel:  *useIpFromLabel,
		ForceTags:       *forceTags,
		RefreshTtl:      *refreshTtl,
		RefreshInterval: *refreshInterval,
		DeregisterCheck: *deregister,
		Cleanup:         *cleanup,
	})

	assert(err)

	//设置retryAttempts为-1时，通过死循环进行无限重试，直到连接成功，跳出死循环
	//设置retryAttempts不为-1时，在重试次数达到上限前，循环进行重试
	attempt := 0
	for *retryAttempts == -1 || attempt <= *retryAttempts {
		log.Printf("Connecting to backend (%v/%v)", attempt, *retryAttempts)

		err = b.Ping()
		if err == nil {
			break
		}

		if err != nil && attempt == *retryAttempts {
			assert(err)
		}

		time.Sleep(time.Duration(*retryInterval) * time.Millisecond)
		attempt++
	}

	// Start event listener before listing containers to avoid missing anything
	//在列出docker容器信息之前启动事件监听器，以避免遗漏任何内容
	//下面创建的events是一个通道，当发生docker容器的创建/销毁时，dockerapi就会把相应的event传递到该通道中
	events := make(chan *dockerapi.APIEvents)
	assert(docker.AddEventListener(events))
	log.Println("Listening for Docker events ...")

	//获取本地docker中的容器信息
	log.Println("First Sync")
	b.Sync(false)

	//创建一个只包含空结构体的通道，常用于通知所有协程退出
	quit := make(chan struct{})

	// Start the TTL refresh timer
	//启动刷新定时器
	if *refreshInterval > 0 {
		ticker := time.NewTicker(time.Duration(*refreshInterval) * time.Second)
		go func() {
			for {
				select {
				case <-ticker.C:
					log.Println("Refresh")
					b.Refresh()
				case <-quit: 	//空结构体的通道无需传入元素，只需读等待阻塞在case语句中，等到close该通道时，才会解除阻塞
					ticker.Stop()
					return
				}
			}
		}()
	}

	// Start the resync timer if enabled
	//启动同步定时器，用于将docker容器的变更信息同步到程序进程中
	if *resyncInterval > 0 {
		resyncTicker := time.NewTicker(time.Duration(*resyncInterval) * time.Second)
		go func() {
			for {
				select {
				case <-resyncTicker.C:
					log.Println("Sync")
					b.Sync(true)
				case <-quit:
					resyncTicker.Stop()
					return
				}
			}
		}()
	}

	// Process Docker events
	//将events转换为storage server中的添加条目或删除条目操作
	//主协程会在这里死循环
	for msg := range events {
		switch msg.Status {
		case "start":
			log.Println("Add")
			go b.Add(msg.ID)
		case "die":
			log.Println("RemoveOnExit")
			go b.RemoveOnExit(msg.ID)
		}
	}

	close(quit)
	log.Fatal("Docker event loop closed") // todo: reconnect?
}
