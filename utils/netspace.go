package utils

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// 从quake获取，结果为IP:PORT
func GetSocksFromQuake(quake QUAKEConfig) {
	defer Wg.Done()
	if quake.Switch != "open" {
		fmt.Println("---未开启quake---")
		return
	}
	fmt.Printf("***已开启quake,将根据配置条件从quake中获取%d条数据，然后进行有效性检测***\n", quake.ResultSize)
	jsonCondition := "{\"query\": \"" + strings.Replace(quake.QueryString, `"`, `\"`, -1) + "\",\"start\": 0,\"size\": " + strconv.Itoa(quake.ResultSize) + ",\"include\":[\"ip\",\"port\"]}"
	headers := map[string]string{
		"X-QuakeToken": quake.Key,
		"Content-Type": "application/json"}
	content, err := fetchContent(quake.APIURL, "POST", 60, nil, headers, jsonCondition)
	if err != nil {
		fmt.Println("quake异常", err)
		return
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(content), &data)
	code, _ := strconv.ParseFloat("0", 64)
	if data["code"] != code {
		fmt.Println("QUAKE:", data["message"])
		return
	}
	arr := data["data"].([]interface{})
	fmt.Println("+++quake数据已取+++")
	for _, item := range arr {
		itemMap := item.(map[string]interface{})
		ip := itemMap["ip"].(string)
		port := itemMap["port"].(float64)
		addSocks(ip + ":" + strconv.FormatFloat(port, 'f', -1, 64))
	}
}

// 从FOFA获取,结果为IP:PORT
func GetSocksFromFofa(fofa FOFAConfig) {
	defer Wg.Done()
	if fofa.Switch != "open" {
		fmt.Println("---未开启fofa---")
		return
	}
	fmt.Printf("***已开启fofa,将根据配置条件从fofa中获取%d条数据，然后进行有效性检测***\n", fofa.ResultSize)

	params := map[string]string{
		"email":   fofa.Email,
		"key":     fofa.Key,
		"fields":  "ip,port",
		"qbase64": base64.URLEncoding.EncodeToString([]byte(fofa.QueryString)),
		"size":    strconv.Itoa(fofa.ResultSize)}
	content, err := fetchContent(fofa.APIURL, "GET", 60, params, nil, "")
	if err != nil {
		fmt.Println("访问fofa异常", err)
		return
	}
	var data map[string]interface{}
	json.Unmarshal([]byte(content), &data)
	if data["error"] == true {
		fmt.Println("FOFA:", data["errmsg"])
		return
	}
	array := data["results"].([]interface{})
	fmt.Println("+++fofa数据已取+++")
	for _, itemArray := range array {
		itemSlice := itemArray.([]interface{})
		addSocks(itemSlice[0].(string) + ":" + itemSlice[1].(string))
	}

}

// 从鹰图获取，结果为IP:PORT
func GetSocksFromHunter(hunter HUNTERConfig) {
	defer Wg.Done()
	if hunter.Switch != "open" {
		fmt.Println("---未开启hunter---")
		return
	}
	fmt.Printf("***已开启hunter,将根据配置条件从hunter中获取%d条数据,然后进行有效性检测***\n", hunter.ResultSize)

	var exeData int //记录处理了几条
	end := hunter.ResultSize / 100
	for i := 1; i <= end; i++ {
		params := map[string]string{
			"api-key":   hunter.Key,
			"search":    base64.URLEncoding.EncodeToString([]byte(hunter.QueryString)),
			"page":      strconv.Itoa(i),
			"page_size": "100"}
		fmt.Printf("HUNTER:每页100条,正在查询第%v页\n", i)
		content, err := fetchContent(hunter.APIURL, "GET", 60, params, nil, "")
		if err != nil {
			fmt.Println("访问hunter异常", err)
			return
		}
		var data map[string]interface{}
		json.Unmarshal([]byte(content), &data)
		code, _ := strconv.ParseFloat("200", 64)
		if data["code"] != code {
			fmt.Println("HUNTER:", data["message"])
			return
		}

		rsData := data["data"].(map[string]interface{})
		total := rsData["total"].(float64)
		if total == 0 {
			fmt.Println("HUNTER:xxx根据配置语法,未取到数据xxx")
			break
		}
		arr := rsData["arr"].([]interface{})
		for _, item := range arr {
			itemMap := item.(map[string]interface{})
			ip := itemMap["ip"].(string)
			port := itemMap["port"].(float64)
			exeData++
			addSocks(ip + ":" + strconv.FormatFloat(port, 'f', -1, 64))
		}
		if float64(exeData) >= total {
			break
		}
		if end > 1 && i != end {
			time.Sleep(3 * time.Second) //防止hunter提示访问过快获取不到结果
		}
	}
	fmt.Println("+++hunter数据已取+++")
}

// 从本地文件获取，格式为IP:PORT
func GetSocksFromFile(socksFileName string) {
	_, err := os.Stat(socksFileName)
	if !os.IsNotExist(err) {
		fmt.Println("***当前目录下存在" + socksFileName + ",将按行读取格式为IP:PORT的socks5代理***")
		file, err := os.Open(socksFileName)
		if err != nil {
			fmt.Println("读取文件"+socksFileName+"异常，略过该文件中的代理，异常信息为:", err)
			return
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)

		for scanner.Scan() {
			line := scanner.Text()
			SocksList = append(SocksList, strings.TrimSpace(line))
		}
		// 检查扫描过程中是否发生了错误
		if err := scanner.Err(); err != nil {
			fmt.Println("Error reading file,请确认文件中的socks5代理是IP:PORT格式:", err)
		}
	} else {
		fmt.Println(socksFileName + "文件不存在，将根据配置信息从网络空间测绘平台取socks5的代理")
	}
}
