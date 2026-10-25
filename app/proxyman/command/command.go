package command

import (
	"context"

	"github.com/xtls/xray-core/app/commander"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/inbound"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/proxy"
	grpc "google.golang.org/grpc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// InboundOperation is the interface for operations that applies to inbound handlers.
type InboundOperation interface {
	// ApplyInbound applies this operation to the given inbound handler.
	ApplyInbound(context.Context, inbound.Handler) error
}

// OutboundOperation is the interface for operations that applies to outbound handlers.
type OutboundOperation interface {
	// ApplyOutbound applies this operation to the given outbound handler.
	ApplyOutbound(context.Context, outbound.Handler) error
}

func getInbound(handler inbound.Handler) (proxy.Inbound, error) {
	gi, ok := handler.(proxy.GetInbound)
	if !ok {
		return nil, errors.New("can't get inbound proxy from handler.")
	}
	return gi.GetInbound(), nil
}

// ApplyInbound implements InboundOperation.
func (op *AddUserOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.UserManager)
	if !ok {
		return errors.New("proxy is not a UserManager")
	}
	mUser, err := op.User.ToMemoryUser()
	if err != nil {
		return errors.New("failed to parse user").Base(err)
	}
	// A block travels in the general user contract, but only a manager that
	// can enforce one honours it. Adding the account to any other protocol
	// would hand the operator an entry that reads as blocked and works.
	if mUser.Disabled {
		if _, ok := p.(proxy.BlockableUserManager); !ok {
			return errors.New("proxy does not support blocked users, refuse to add ", mUser.Email, " as one")
		}
	}
	return um.AddUser(ctx, mUser)
}

// ApplyInbound implements InboundOperation.
func (op *RemoveUserOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.UserManager)
	if !ok {
		return errors.New("proxy is not a UserManager")
	}
	return um.RemoveUser(ctx, op.Email)
}

// ApplyInbound implements InboundOperation.
func (op *BlockUserOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.BlockableUserManager)
	if !ok {
		return errors.New("proxy is not a BlockableUserManager")
	}
	return um.SetUserBlocked(ctx, op.Email, op.Blocked)
}

// ApplyInbound implements InboundOperation.
func (op *SetUserMaxSessionsOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.TunableUserManager)
	if !ok {
		return errors.New("proxy does not support per-user session limits")
	}
	return um.SetUserMaxSessions(ctx, op.Email, op.MaxSessionsPerUser)
}

// ApplyInbound implements InboundOperation.
func (op *SetUserL3Operation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.TunableUserManager)
	if !ok {
		return errors.New("proxy does not support per-user L3 overrides")
	}
	return um.SetUserL3(ctx, op.Email, op.L3)
}

// ApplyInbound implements InboundOperation.
func (op *DisconnectUserOperation) ApplyInbound(ctx context.Context, handler inbound.Handler) error {
	p, err := getInbound(handler)
	if err != nil {
		return err
	}
	um, ok := p.(proxy.DisconnectableUserManager)
	if !ok {
		return errors.New("proxy does not support disconnecting users")
	}
	return um.DisconnectUser(ctx, op.Email)
}

type handlerServer struct {
	s   *core.Instance
	ihm inbound.Manager
	ohm outbound.Manager
}

func (s *handlerServer) AddInbound(ctx context.Context, request *AddInboundRequest) (*AddInboundResponse, error) {
	if err := core.AddInboundHandler(s.s, request.Inbound); err != nil {
		return nil, err
	}

	return &AddInboundResponse{}, nil
}

func (s *handlerServer) RemoveInbound(ctx context.Context, request *RemoveInboundRequest) (*RemoveInboundResponse, error) {
	return &RemoveInboundResponse{}, s.ihm.RemoveHandler(ctx, request.Tag)
}

func (s *handlerServer) AlterInbound(ctx context.Context, request *AlterInboundRequest) (*AlterInboundResponse, error) {
	rawOperation, err := request.Operation.GetInstance()
	if err != nil {
		return nil, errors.New("unknown operation").Base(err)
	}
	operation, ok := rawOperation.(InboundOperation)
	if !ok {
		return nil, errors.New("not an inbound operation")
	}

	handler, err := s.ihm.GetHandler(ctx, request.Tag)
	if err != nil {
		return nil, errors.New("failed to get handler: ", request.Tag).Base(err)
	}

	return &AlterInboundResponse{}, operation.ApplyInbound(ctx, handler)
}

func (s *handlerServer) ListInbounds(ctx context.Context, request *ListInboundsRequest) (*ListInboundsResponse, error) {
	handlers := s.ihm.ListHandlers(ctx)
	response := &ListInboundsResponse{}
	if request.GetIsOnlyTags() {
		for _, handler := range handlers {
			response.Inbounds = append(response.Inbounds, &core.InboundHandlerConfig{
				Tag: handler.Tag(),
			})
		}
	} else {
		for _, handler := range handlers {
			response.Inbounds = append(response.Inbounds, &core.InboundHandlerConfig{
				Tag:              handler.Tag(),
				ReceiverSettings: handler.ReceiverSettings(),
				ProxySettings:    handler.ProxySettings(),
			})
		}
	}

	return response, nil
}

// redactUser masks the credential an account carries. The commander socket is
// not authenticated, and an OpenConnect account is a salted hash: handed out,
// it can be attacked offline at leisure. Everything the operator lists users
// for — name, static address, group, the block flag — survives; the secret
// does not.
//
// In its place goes a fingerprint, because the loop reading this listing has to
// notice that an account's credential changed. It can: a customer who changed
// their password is still authenticated by the old one until the inbound is
// rewritten, and this listing is the only place the loop can learn that. The
// digest answers that without anything reversible leaving the node.
//
// The user passed in was just built by protocol.ToProtoUser, so writing to it
// cannot reach the live store.
func redactUser(u *protocol.User) *protocol.User {
	if u == nil || u.Account == nil {
		return u
	}
	raw, err := u.Account.GetInstance()
	if err != nil {
		// An account this build cannot decode cannot be inspected for a
		// credential either, so none of it goes out.
		u.Account = &serial.TypedMessage{Type: u.Account.Type}
		return u
	}
	ref := raw.ProtoReflect()
	if fd := ref.Descriptor().Fields().ByName("password"); fd != nil && fd.Kind() == protoreflect.StringKind {
		// An account carrying no credential keeps reporting none. A digest of
		// the empty string would read as a credential the loop could match
		// against, and an absent one is what tells the loop to compare nothing.
		if secret := ref.Get(fd).String(); secret != "" {
			ref.Set(fd, protoreflect.ValueOfString(protocol.CredentialFingerprint(secret)))
		} else {
			ref.Clear(fd)
		}
	}
	u.Account = serial.ToTypedMessage(raw)
	return u
}

func (s *handlerServer) GetInboundUsers(ctx context.Context, request *GetInboundUserRequest) (*GetInboundUserResponse, error) {
	handler, err := s.ihm.GetHandler(ctx, request.Tag)
	if err != nil {
		return nil, errors.New("failed to get handler: ", request.Tag).Base(err)
	}
	p, err := getInbound(handler)
	if err != nil {
		return nil, err
	}
	um, ok := p.(proxy.UserManager)
	if !ok {
		return nil, errors.New("proxy is not a UserManager")
	}
	if len(request.Email) > 0 {
		return &GetInboundUserResponse{Users: []*protocol.User{redactUser(protocol.ToProtoUser(um.GetUser(ctx, request.Email)))}}, nil
	}
	result := make([]*protocol.User, 0, 100)
	users := um.GetUsers(ctx)
	for _, u := range users {
		result = append(result, redactUser(protocol.ToProtoUser(u)))
	}
	return &GetInboundUserResponse{Users: result}, nil
}

func (s *handlerServer) GetInboundUsersCount(ctx context.Context, request *GetInboundUserRequest) (*GetInboundUsersCountResponse, error) {
	handler, err := s.ihm.GetHandler(ctx, request.Tag)
	if err != nil {
		return nil, errors.New("failed to get handler: ", request.Tag).Base(err)
	}
	p, err := getInbound(handler)
	if err != nil {
		return nil, err
	}
	um, ok := p.(proxy.UserManager)
	if !ok {
		return nil, errors.New("proxy is not a UserManager")
	}
	return &GetInboundUsersCountResponse{Count: um.GetUsersCount(ctx)}, nil
}

func (s *handlerServer) AddOutbound(ctx context.Context, request *AddOutboundRequest) (*AddOutboundResponse, error) {
	if err := core.AddOutboundHandler(s.s, request.Outbound); err != nil {
		return nil, err
	}
	return &AddOutboundResponse{}, nil
}

func (s *handlerServer) RemoveOutbound(ctx context.Context, request *RemoveOutboundRequest) (*RemoveOutboundResponse, error) {
	return &RemoveOutboundResponse{}, s.ohm.RemoveHandler(ctx, request.Tag)
}

func (s *handlerServer) AlterOutbound(ctx context.Context, request *AlterOutboundRequest) (*AlterOutboundResponse, error) {
	rawOperation, err := request.Operation.GetInstance()
	if err != nil {
		return nil, errors.New("unknown operation").Base(err)
	}
	operation, ok := rawOperation.(OutboundOperation)
	if !ok {
		return nil, errors.New("not an outbound operation")
	}

	handler := s.ohm.GetHandler(request.Tag)
	return &AlterOutboundResponse{}, operation.ApplyOutbound(ctx, handler)
}

func (s *handlerServer) ListOutbounds(ctx context.Context, request *ListOutboundsRequest) (*ListOutboundsResponse, error) {
	handlers := s.ohm.ListHandlers(ctx)
	response := &ListOutboundsResponse{}
	for _, handler := range handlers {
		// Ignore gRPC outbound
		if _, ok := handler.(*commander.Outbound); ok {
			continue
		}
		response.Outbounds = append(response.Outbounds, &core.OutboundHandlerConfig{
			Tag:            handler.Tag(),
			SenderSettings: handler.SenderSettings(),
			ProxySettings:  handler.ProxySettings(),
		})
	}
	return response, nil
}

func (s *handlerServer) mustEmbedUnimplementedHandlerServiceServer() {}

type service struct {
	v *core.Instance
}

func (s *service) Register(server *grpc.Server) {
	hs := &handlerServer{
		s: s.v,
	}
	common.Must(s.v.RequireFeatures(func(im inbound.Manager, om outbound.Manager) {
		hs.ihm = im
		hs.ohm = om
	}, false))
	RegisterHandlerServiceServer(server, hs)

	// For compatibility purposes
	vCoreDesc := HandlerService_ServiceDesc
	vCoreDesc.ServiceName = "v2ray.core.app.proxyman.command.HandlerService"
	server.RegisterService(&vCoreDesc, hs)
}

func init() {
	common.Must(common.RegisterConfig((*Config)(nil), func(ctx context.Context, cfg interface{}) (interface{}, error) {
		s := core.MustFromContext(ctx)
		return &service{v: s}, nil
	}))
}
