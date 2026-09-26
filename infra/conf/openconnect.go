package conf

import (
	"github.com/xtls/xray-core/proxy/openconnect"
	"google.golang.org/protobuf/proto"
)

type OpenConnectUserConfig struct {
	Name     string   `json:"name"`
	Password string   `json:"password"`
	IP       string   `json:"ip,omitempty"`
	Routes   []string `json:"routes,omitempty"`
	Group    string   `json:"group,omitempty"`
	L3       bool     `json:"l3,omitempty"`
}

type OpenConnectGroupConfig struct {
	Name   string   `json:"name"`
	Routes []string `json:"routes"`
}

type OpenConnectConfig struct {
	Users            []OpenConnectUserConfig  `json:"users"`
	Subnet           string                   `json:"subnet"`
	DNS              []string                 `json:"dns,omitempty"`
	Routes           []string                 `json:"routes,omitempty"`
	MTU              uint32                   `json:"mtu"`
	DPD              uint32                   `json:"dpd"`
	CookieTimeout    uint32                   `json:"cookieTimeout"`
	CertFile         string                   `json:"certFile"`
	KeyFile          string                   `json:"keyFile"`
	MaxClients       uint32                   `json:"maxClients"`
	DtlsPort         uint32                   `json:"dtlsPort"`
	CamouflageSecret string                   `json:"camouflageSecret,omitempty"`
	CamouflageRealm  string                   `json:"camouflageRealm,omitempty"`
	Groups           []OpenConnectGroupConfig `json:"groups,omitempty"`
}

func (c *OpenConnectConfig) Build() (proto.Message, error) {
	config := new(openconnect.OpenConnectInboundConfig)
	config.Users = make([]*openconnect.User, len(c.Users))
	for i := range c.Users {
		config.Users[i] = &openconnect.User{
			Name:     c.Users[i].Name,
			Password: c.Users[i].Password,
			Ip:       c.Users[i].IP,
			Routes:   c.Users[i].Routes,
			Group:    c.Users[i].Group,
			L3:       c.Users[i].L3,
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
	config.CamouflageSecret = c.CamouflageSecret
	config.CamouflageRealm = c.CamouflageRealm
	config.Groups = make([]*openconnect.Group, len(c.Groups))
	for i := range c.Groups {
		config.Groups[i] = &openconnect.Group{
			Name:   c.Groups[i].Name,
			Routes: c.Groups[i].Routes,
		}
	}
	return config, nil
}
