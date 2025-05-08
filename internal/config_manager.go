package internal

import "log"

func LoadConfig(filePath string) (*OpenVPNOptions, error) {
	return ReadConfigFile(filePath)
}

func InitConfig() {
	config, err := LoadConfig("test.ovpn")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	//// Передача настроек в другие модули
	//\\tunnelManager.SetTunnelConfig(config.Remote, config.Port, config.Proto)
	//cryptoManager.SetCryptoConfig(config.Cipher, config.Auth, config.TLSMaxVer)
	//AuthManager.SetAuthConfig(config.Username, config.Password, config.Cert, config.Key, config.CA)
	println(config)
}
