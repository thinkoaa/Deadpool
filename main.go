package main

import (
	"Deadpool/utils"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/armon/go-socks5"
)

func main() {

	utils.Banner()
	fmt.Println("By:thinkoaa GitHub:https://github.com/thinkoaa/Deadpool\n\n")
	//读取配置文件
	config, err := utils.LoadConfig("config.toml")
	if err != nil {
		fmt.Printf("读取config.toml失败,请检查配置,格式一定要正确%w\n", err)
		os.Exit(1)
	}

	//从本地文件中取socks代理
	fmt.Println("***直接使用fmt打印当前使用的代理,若高并发时,命令行打印可能会阻塞，不对打印做特殊处理，可忽略，不会影响实际的请求转发***\n")
	utils.GetSocksFromFile(utils.LastDataFile)
	//从fofa获取
	utils.Wg.Add(1)
	go utils.GetSocksFromFofa(config.FOFA)
	//从hunter获取
	utils.Wg.Add(1)
	go utils.GetSocksFromHunter(config.HUNTER)
	//从quake中取
	utils.Wg.Add(1)
	go utils.GetSocksFromQuake(config.QUAKE)
	utils.Wg.Wait()
	//等待所有 goroutine 完成
	if len(utils.SocksList) == 0 {
		fmt.Println("未发现代理数据,请调整配置信息,或向" + utils.LastDataFile + "中直接写入IP:PORT格式的socks5代理,\n程序退出")
		os.Exit(1)
	}

	//根据IP:PORT去重，此步骤会存在同IP不同端口的情况，这种情况不再单独过滤，这种情况，最终的出口IP可能不一样
	utils.RemoveDuplicates()
	fmt.Printf("根据IP:PORT去重后，共发现%v个代理\n检测可用性中......\n", len(utils.SocksList))

	//开始检测代理存活性
	startTime := time.Now()
	utils.Timeout = config.CheckSocks.Timeout
	utils.CheckSocks(config.CheckSocks)

	sec := int(time.Since(startTime).Seconds())
	if sec == 0 {
		sec = 1
	}
	fmt.Printf("\n根据配置规则检测完成,用时 [ %vs ] ,共发现 [ %v ] 个可用\n", sec, len(utils.EffectiveList))
	if len(utils.EffectiveList) == 0 {
		fmt.Println("根据规则检测后，未发现满足要求的代理,请调整配置,程序退出")
		os.Exit(1)
	}

	utils.WriteLinesToFile() //存活代理写入硬盘，以备下次启动直接读取

	// 开启监听
	conf := &socks5.Config{
		Dial:   utils.DefineDial,
		Logger: log.New(io.Discard, "", log.LstdFlags),
	}
	userName := strings.TrimSpace(config.Listener.UserName)
	password := strings.TrimSpace(config.Listener.Password)
	if userName != "" && password != "" {
		cator := socks5.UserPassAuthenticator{Credentials: socks5.StaticCredentials{
			userName: password,
		}}
		conf.AuthMethods = []socks5.Authenticator{cator}
	}
	server, _ := socks5.New(conf)
	listener := config.Listener.IP + ":" + strconv.Itoa(config.Listener.Port)
	fmt.Printf("======其他工具通过配置 socks5://%v 使用收集的代理,如有账号密码，记得配置======\n", listener)
	if err := server.ListenAndServe("tcp", listener); err != nil {
		fmt.Printf("本地监听服务启动失败：%v\n", err)
		os.Exit(1)
	}

}
