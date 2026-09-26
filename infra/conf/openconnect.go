package conf

import (
	"github.com/xtls/xray-core/proxy/openconnect"
	"google.golang.org/protobuf/proto"
)

type OpenConnectUserConfig struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	IP       string `json:"ip,omitempty"`
}

type OpenConnectConfig struct {
	Users         []OpenConnectUserConfig `json:"users"`
	Subnet        string                  `json:"subnet"`
	DNS           []string                `json:"dns,omitempty"`
	Routes        []string                `json:"routes,omitempty"`
	MTU           uint32                  `json:"mtu"`
	DPD           uint32                  `json:"dpd"`
	CookieTimeout uint32                  `json:"cookieTimeout"`
	CertFile      string                  `json:"certFile"`
	KeyFile       string                  `json:"keyFile"`
	MaxClients    uint32                  `json:"maxClients"`
	DtlsPort      uint32                  `json:"dtlsPort"`
}

func (c *OpenConnectConfig) Build() (proto.Message, error) {
	config := new(openconnect.OpenConnectInboundConfig)
	config.Users = make([]*openconnect.User, len(c.Users))
	for i := range c.Users {
		config.Users[i] = &openconnect.User{
			Name:     c.Users[i].Name,
			Password: c.Users[i].Password,
			Ip:       c.Users[i].IP,
		}
	}
	config.Subnet = c.Subnet
	config.Dns = c.DNS
	config.Routes = c.Routes
	config.Mtu = c.MTU
	config.Dpd = c.DPD
	config.CookieTimeout = c.CookieTimeout
	config.CertFile = c.CertFile
	config.KeyFile = c.KeyFile
	config.MaxClients = c.MaxClients
	config.DtlsPort = c.DtlsPort
	return config, nil
}
