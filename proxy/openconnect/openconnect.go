package openconnect

import (
	"context"

	"github.com/xtls/xray-core/common"
)

func init() {
	common.Must(common.RegisterConfig((*OpenConnectInboundConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewServer(ctx, config.(*OpenConnectInboundConfig))
	}))
}
