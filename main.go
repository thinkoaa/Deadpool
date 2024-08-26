package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
)

var (
	socksList     []string
	effectiveList []string
	proxyIndex    int
	timeout       int
	lastDataFile  = "lastData.txt"
	wg            sync.WaitGroup
	mu            sync.Mutex
	semaphore     chan struct{}
)

func main() {

	// 设置 log 包的输出目标为文件
	fmt.Println(strings.Repeat("*", 100))
	fmt.Println(strings.Repeat(" ", 25) + "By:thinkoaa GitHub:https://github.com/thinkoaa/Deadpool")
	fmt.Println(strings.Repeat("*", 100))
	//读取配置文件
	var config map[string]interface{}
	if _, err := toml.DecodeFile("config.toml", &config); err != nil {
		fmt.Println("读取config.toml失败,请检查配置,格式一定要正确", err)
		os.Exit(1)
	}
	// 开启监听
	listenerConfig := config["listener"].(map[string]interface{})
	listener := listenerConfig["IP"].(string) + ":" + listenerConfig["PORT"].(string)
	socketServer, err := net.Listen("tcp", listener)
	if err != nil {
		fmt.Printf("本地监听服务启动失败：%v\n", err)
		os.Exit(1)
	}
	//从本地文件中取socks代理，速度快不异步
	GetSocksFromFile(lastDataFile)
	//从fofa获取
	wg.Add(1)
	go getSocksFromFofa(config["FOFA"].(map[string]interface{}))
	//从hunter获取
	wg.Add(1)
	go getSocksFromHunter(config["HUNTER"].(map[string]interface{}))
	//从quake中取
	wg.Add(1)
	go getSocksFromQuake(config["QUAKE"].(map[string]interface{}))
	//等待所有 goroutine 完成
	wg.Wait()
	if len(socksList) == 0 {
		fmt.Println("未发现代理数据,请调整配置信息,或向" + lastDataFile + "中直接写入IP:PORT格式的socks5代理,\n程序退出")
		os.Exit(1)
	}
	//根据IP:PORT去重，此步骤会存在同IP不同端口的情况，这种情况不再单独过滤，这种情况，最终的出口IP可能不一样
	socksList = removeDuplicates(socksList)
	fmt.Printf("根据IP:PORT去重后，共发现%v个代理\n检测可用性中......\n", len(socksList))

	//开始检测代理存活性
	startTime := time.Now()
	checkSocks(config["checkSocks"].(map[string]interface{}))
	wg.Wait()
	sec := int(time.Since(startTime).Seconds())
	if sec == 0 {
		sec = 1
	}
	fmt.Printf("\n根据配置规则检测完成,用时 %vs ,共发现%v个可用\n", sec, len(effectiveList))
	if len(effectiveList) == 0 {
		fmt.Println("根据规则检测后，未发现满足要求的代理,请调整配置,程序退出")
		os.Exit(1)
	}

	WriteLinesToFile(lastDataFile, effectiveList) //存活代理写入硬盘，以备下次启动直接读取

	fmt.Printf("======其他工具通过配置 socks5://%v 使用收集的代理，此处若提示0.0.0.0:xxxx，使用时需指定为具体地址======\n***直接使用fmt打印当前使用的代理,若高并发时,命令行打印可能会阻塞，不对打印做特殊处理，可忽略，不会影响实际的请求转发***\n", listener)
	for { //持续监听请求
		reqFromClient, err := socketServer.Accept()
		if err != nil {
			fmt.Printf("本次客户端发起的请求出错：%v\n", err)
			continue
		}
		go transmitReqFromClient(reqFromClient)
	}
}

func transmitReqFromClient(reqFromClient net.Conn) {
	defer reqFromClient.Close()
	tmpProxy := getNextProxy()
	fmt.Println(time.Now().Format("2006-01-02 15:04:05") + "    " + tmpProxy)
	if len(effectiveList) == 0 {
		fmt.Println("***已无可用代理，程序退出***")
		os.Exit(1)
	}
	if len(effectiveList) <= 1 {
		fmt.Printf("***可用代理已仅剩%v个,%v，***\n", len(effectiveList), effectiveList)
	}

	conn, err := net.DialTimeout("tcp", tmpProxy, time.Duration(timeout)*time.Second)
	if err != nil {
		delInvalidProxy(tmpProxy) //从临时列表中删除该代理
		transmitReqFromClient(reqFromClient)
		return
	}
	defer conn.Close()
	go io.Copy(conn, reqFromClient)
	io.Copy(reqFromClient, conn)
}

func getNextProxy() string {
	mu.Lock()
	defer mu.Unlock()
	proxy := effectiveList[proxyIndex]
	proxyIndex = (proxyIndex + 1) % len(effectiveList) // 循环访问
	return proxy
}

// 使用过程中删除无效的代理
func delInvalidProxy(proxy string) {
	mu.Lock()
	for i, p := range effectiveList {
		if p == proxy {
			effectiveList = append(effectiveList[:i], effectiveList[i+1:]...)
			if proxyIndex != 0 {
				proxyIndex = proxyIndex - 1
			}
			break
		}
	}
	if proxyIndex >= len(effectiveList) {
		proxyIndex = 0
	}
	mu.Unlock()
}
