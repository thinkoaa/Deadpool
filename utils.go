package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// 防止goroutine 异步处理问题
func addSocks(socks5 string) {
	mu.Lock()
	socksList = append(socksList, socks5)
	mu.Unlock()
}
func fetchContent(baseURL string, method string, timeout int, urlParams map[string]string, headers map[string]string, jsonBody string) (string, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: time.Duration(timeout) * time.Second,
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	if urlParams != nil {
		q := u.Query()
		for key, value := range urlParams {
			q.Set(key, value)
		}
		u.RawQuery = q.Encode()
	}

	var req *http.Request
	if jsonBody != "" {
		req, err = http.NewRequest(method, u.String(), bytes.NewBufferString(jsonBody))
	} else {
		req, err = http.NewRequest(method, u.String(), nil)
	}

	if err != nil {
		return "", err
	}
	req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
	if len(headers) != 0 {
		for key, value := range headers {
			req.Header.Add(key, value)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func removeDuplicates(socksList []string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, sock := range socksList {
		if _, ok := seen[sock]; !ok {
			result = append(result, sock)
			seen[sock] = struct{}{}
		}
	}

	return result
}
func checkSocks(config map[string]interface{}) {
	maxConcurrentReq, _ := strconv.Atoi(config["maxConcurrentReq"].(string))
	timeout, _ = strconv.Atoi(config["timeout"].(string))
	semaphore = make(chan struct{}, maxConcurrentReq)

	checkRspKeywords := config["checkRspKeywords"].(string)
	checkGeolocateConfig := config["checkGeolocate"].(map[string]interface{})
	checkGeolocateSwitch := checkGeolocateConfig["switch"].(string)
	isOpenGeolocateSwitch := false
	reqUrl := config["checkURL"].(string)
	if checkGeolocateSwitch == "open" {
		isOpenGeolocateSwitch = true
		reqUrl = checkGeolocateConfig["checkURL"].(string)
	}
	for _, proxyAddr := range socksList {

		wg.Add(1)
		semaphore <- struct{}{}
		go func(proxyAddr string) {
			defer wg.Done()
			defer func() {
				<-semaphore

			}()
			socksProxy := "socks5://" + proxyAddr
			proxy := func(_ *http.Request) (*url.URL, error) {
				return url.Parse(socksProxy)
			}
			tr := &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				Proxy:           proxy,
			}
			client := &http.Client{
				Transport: tr,
				Timeout:   time.Duration(timeout) * time.Second,
			}
			req, err := http.NewRequest("GET", reqUrl, nil)
			if err != nil {
				return
			}
			req.Header.Add("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36 Edg/112.0.1722.17")
			req.Header.Add("referer", "https://www.baidu.com/s?ie=utf-8&f=8&rsv_bp=1&rsv_idx=1&tn=baidu&wd=ip&fenlei=256&rsv_pq=0xc23dafcc00076e78&rsv_t=6743gNBuwGYWrgBnSC7Yl62e52x3CKQWYiI10NeKs73cFjFpwmqJH%2FOI%2FSRG&rqlang=en&rsv_dl=tb&rsv_enter=1&rsv_sug3=5&rsv_sug1=5&rsv_sug7=101&rsv_sug2=0&rsv_btype=i&prefixsug=ip&rsp=4&inputT=2165&rsv_sug4=2719")
			resp, err := client.Do(req)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				// fmt.Printf("+++++++代理不可用：%v+++++++\n", proxyAddr)
				return
			}
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				// fmt.Printf("%v: %v\n", proxyAddr, err)
				return
			}
			stringBody := string(body)
			if !isOpenGeolocateSwitch {
				if strings.Contains(stringBody, checkRspKeywords) {
					mu.Lock() // 锁
					effectiveList = append(effectiveList, proxyAddr)
					message := "\r已发现第 " + strconv.Itoa(len(effectiveList)) + " 个符合条件的代理:" + proxyAddr + "        "
					messageBytes := []byte(message)
					os.Stdout.Write(messageBytes)
					mu.Unlock() // 解锁
				}
			} else {
				//直接循环要排除的关键字，任一命中就返回
				for _, keyword := range checkGeolocateConfig["excludeKeywords"].([]interface{}) {
					if strings.Contains(stringBody, keyword.(string)) {
						// fmt.Println("忽略：" + proxyAddr + "包含：" + keyword.(string))
						return
					}
				}
				//直接循环要必须包含的关键字，任一未命中就返回
				for _, keyword := range checkGeolocateConfig["includeKeywords"].([]interface{}) {
					if !strings.Contains(stringBody, keyword.(string)) {
						// fmt.Println("忽略：" + proxyAddr + "未包含：" + keyword.(string))
						return
					}
				}
				mu.Lock() // 锁
				effectiveList = append(effectiveList, proxyAddr)
				message := "\r已发现第 " + strconv.Itoa(len(effectiveList)) + " 个符合条件代理:" + proxyAddr + "        "
				messageBytes := []byte(message)
				os.Stdout.Write(messageBytes)
				mu.Unlock() // 解锁

			}
		}(proxyAddr)
	}
}

func WriteLinesToFile(fileName string, lines []string) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}
