package utils

import (
	"os"

	toml "github.com/pelletier/go-toml/v2"
)

type Config struct {
	Listener   ListenerConfig   `toml:"listener"`
	Task       TaskConfig       `toml:"task"`
	CheckSocks CheckSocksConfig `toml:"checkSocks"`
	FOFA       FOFAConfig       `toml:"FOFA"`
	QUAKE      QUAKEConfig      `toml:"QUAKE"`
	HUNTER     HUNTERConfig     `toml:"HUNTER"`
}

type ListenerConfig struct {
	IP       string `toml:"IP"`
	Port     int    `toml:"PORT"`
	UserName string `toml:"userName"`
	Password string `toml:"password"`
}

type TaskConfig struct {
	PeriodicChecking string `toml:"periodicChecking"`
	PeriodicGetSocks string `toml:"periodicGetSocks"`
}

type CheckSocksConfig struct {
	CheckURL         string               `toml:"checkURL"`
	CheckRspKeywords string               `toml:"checkRspKeywords"`
	MaxConcurrentReq int                  `toml:"maxConcurrentReq"`
	Timeout          int                  `toml:"timeout"`
	CheckGeolocate   CheckGeolocateConfig `toml:"checkGeolocate"`
}

type CheckGeolocateConfig struct {
	Switch          string   `toml:"switch"`
	CheckURL        string   `toml:"checkURL"`
	ExcludeKeywords []string `toml:"excludeKeywords"`
	IncludeKeywords []string `toml:"includeKeywords"`
}

type FOFAConfig struct {
	Switch      string `toml:"switch"`
	APIURL      string `toml:"apiUrl"`
	Email       string `toml:"email"`
	Key         string `toml:"key"`
	QueryString string `toml:"queryString"`
	ResultSize  int    `toml:"resultSize"`
}

type QUAKEConfig struct {
	Switch      string `toml:"switch"`
	APIURL      string `toml:"apiUrl"`
	Key         string `toml:"key"`
	QueryString string `toml:"queryString"`
	ResultSize  int    `toml:"resultSize"`
}

type HUNTERConfig struct {
	Switch      string `toml:"switch"`
	APIURL      string `toml:"apiUrl"`
	Key         string `toml:"key"`
	QueryString string `toml:"queryString"`
	ResultSize  int    `toml:"resultSize"`
}

func LoadConfig(path string) (Config, error) {
	var config Config
	// 读取并解析 TOML 文件
	data, err := os.ReadFile(path)
	if err != nil {
		return config, err
	}

	err = toml.Unmarshal(data, &config)

	return config, err
}
