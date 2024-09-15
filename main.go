package main

import (
	"Deadpool/utils"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/robfig/cron/v3"
)

func main() {
	utils.Banner()
	fmt.Print("By:thinkoaa GitHub:https://github.com/thinkoaa/Deadpool\n\n\n")
	//读取配置文件
	config, err := utils.LoadConfig("config.toml")
	if err != nil {
		fmt.Printf("config.toml配置文件存在错误字符: %d\n", err) //通过%d弹出错误的细节
		os.Exit(1)
	}

	//从本地文件中取socks代理
	fmt.Print("***直接使用fmt打印当前使用的代理,若高并发时,命令行打印可能会阻塞，不对打印做特殊处理，可忽略，不会影响实际的请求转发***\n\n")
	utils.GetSocks(config)
	if len(utils.SocksList) == 0 {
		fmt.Println("未发现代理数据,请调整配置信息,或向" + utils.LastDataFile + "中直接写入IP:PORT格式的socks5代理\n程序退出")
		os.Exit(1)
	}
	fmt.Printf("根据IP:PORT去重后，共发现%v个代理\n检测可用性中......\n", len(utils.SocksList))

	//开始检测代理存活性

	utils.Timeout = config.CheckSocks.Timeout
	utils.CheckSocks(config.CheckSocks, utils.SocksList)
	//根据配置，定时检测内存中的代理存活信息
	cron := cron.New()
	periodicChecking := strings.TrimSpace(config.Task.PeriodicChecking)
	cronFlag := false
	if periodicChecking != "" {
		cronFlag = true
		cron.AddFunc(periodicChecking, func() {
			fmt.Printf("\n===代理存活自检 开始===\n\n")
			tempList := make([]string, len(utils.EffectiveList))
			copy(tempList, utils.EffectiveList)
			utils.CheckSocks(config.CheckSocks, tempList)
			fmt.Printf("\n===代理存活自检 结束===\n\n")
		})
	}
	//根据配置信息，周期性取本地以及hunter、quake、fofa的数据
	periodicGetSocks := strings.TrimSpace(config.Task.PeriodicGetSocks)
	if periodicGetSocks != "" {
		cronFlag = true
		cron.AddFunc(periodicGetSocks, func() {
			fmt.Printf("\n===周期性取代理数据 开始===\n\n")
			utils.SocksList = utils.SocksList[:0]
			utils.GetSocks(config)
			fmt.Printf("根据IP:PORT去重后，共发现%v个代理\n检测可用性中......\n", len(utils.SocksList))
			utils.CheckSocks(config.CheckSocks, utils.SocksList)
			if len(utils.EffectiveList) != 0 {
				utils.WriteLinesToFile() //存活代理写入硬盘，以备下次启动直接读取
			}
			fmt.Printf("\n===周期性取代理数据 结束===\n\n")

		})
	}

	if cronFlag {
		cron.Start()
	}

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
