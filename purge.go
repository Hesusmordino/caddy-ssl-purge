package caddycachepurge

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"sync"
	"time"
	"unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(RedisCertPurge{})
	httpcaddyfile.RegisterGlobalOption("redis_cert_purge", parseRedisCertPurge)
}

type RedisCertPurge struct {
	Address  string `json:"address,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db,omitempty"`
	Channel  string `json:"channel,omitempty"`

	logger    *zap.Logger
	client    *redis.Client
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	certCache *certmagic.Cache
}

func (RedisCertPurge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "redis_cert_purge",
		New: func() caddy.Module { return new(RedisCertPurge) },
	}
}

func (p *RedisCertPurge) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger()

	if p.Address == "" {
		p.Address = "localhost:6379"
	}
	if p.Channel == "" {
		p.Channel = "caddy:cert:purge"
	}

	p.client = redis.NewClient(&redis.Options{
		Addr:     p.Address,
		Username: p.Username,
		Password: p.Password,
		DB:       p.DB,
	})

	if err := p.client.Ping(context.Background()).Err(); err != nil {
		return err
	}

	tlsAppIface, err := ctx.App("tls")
	if err != nil {
		return fmt.Errorf("failed to get tls app: %v", err)
	}

	p.certCache = extractCertCache(tlsAppIface)
	if p.certCache == nil {
		p.logger.Warn("could not extract cert cache from tls app")
	}

	return nil
}

func extractCertCache(tlsApp interface{}) *certmagic.Cache {
	tlsVal := reflect.ValueOf(tlsApp)
	if tlsVal.Kind() == reflect.Ptr {
		tlsVal = tlsVal.Elem()
	}

	automationField := tlsVal.FieldByName("Automation")
	if !automationField.IsValid() || automationField.IsNil() {
		return nil
	}

	return extractCacheFromPolicy(automationField.Elem())
}

func extractCacheFromPolicy(automationVal reflect.Value) *certmagic.Cache {
	for _, fieldName := range []string{"defaultPublicAutomationPolicy", "defaultInternalAutomationPolicy"} {
		policyField := automationVal.FieldByName(fieldName)
		if !policyField.IsValid() || policyField.IsNil() {
			continue
		}
		if cache := extractCacheFromMagic(policyField.Elem()); cache != nil {
			return cache
		}
	}

	policiesField := automationVal.FieldByName("Policies")
	if policiesField.IsValid() {
		for i := 0; i < policiesField.Len(); i++ {
			policy := policiesField.Index(i)
			if policy.Kind() == reflect.Ptr {
				policy = policy.Elem()
			}
			if cache := extractCacheFromMagic(policy); cache != nil {
				return cache
			}
		}
	}

	return nil
}

func extractCacheFromMagic(policyVal reflect.Value) *certmagic.Cache {
	magicField := policyVal.FieldByName("magic")
	if !magicField.IsValid() || magicField.IsNil() {
		return nil
	}

	magicVal := magicField.Elem()
	cacheField := magicVal.FieldByName("certCache")
	if !cacheField.IsValid() || cacheField.IsNil() {
		return nil
	}

	return (*certmagic.Cache)(unsafe.Pointer(cacheField.Pointer()))
}

func (p *RedisCertPurge) Validate() error {
	return nil
}

func (p *RedisCertPurge) Start() error {
	p.ctx, p.cancel = context.WithCancel(context.Background())

	p.wg.Add(1)
	go p.subscribeLoop()

	p.logger.Info("redis cert purge started",
		zap.String("address", p.Address),
		zap.String("channel", p.Channel),
		zap.String("username", p.Username),
	)

	return nil
}

func (p *RedisCertPurge) Stop() error {
	if p.cancel != nil {
		p.cancel()
	}
	p.wg.Wait()

	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

func (p *RedisCertPurge) Cleanup() error {
	return p.Stop()
}

type PurgeMessage struct {
	Domain string `json:"domain"`
}

func (p *RedisCertPurge) subscribeLoop() {
	defer p.wg.Done()

	backoff := time.Second
	maxBackoff := 30 * time.Second

	for {
		select {
		case <-p.ctx.Done():
			p.logger.Info("redis subscriber stopped")
			return
		default:
		}

		p.logger.Info("connecting to redis for subscribe",
			zap.String("address", p.Address),
			zap.String("channel", p.Channel),
		)

		pubsub := p.client.Subscribe(p.ctx, p.Channel)

		if _, err := pubsub.Receive(p.ctx); err != nil {
			p.logger.Error("redis subscribe failed", zap.Error(err))
			pubsub.Close()
			p.sleepWithContext(backoff)
			backoff = p.nextBackoff(backoff, maxBackoff)
			continue
		}

		p.logger.Info("redis subscribed",
			zap.String("channel", p.Channel),
		)

		backoff = time.Second
		ch := pubsub.Channel()

	loop:
		for {
			select {
			case <-p.ctx.Done():
				pubsub.Close()
				return

			case msg, ok := <-ch:
				if !ok {
					p.logger.Warn("redis channel closed, reconnecting")
					break loop
				}
				p.handleMessage(msg.Payload)
			}
		}

		pubsub.Close()
		p.sleepWithContext(backoff)
		backoff = p.nextBackoff(backoff, maxBackoff)
	}
}

func (p *RedisCertPurge) sleepWithContext(d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()

	select {
	case <-p.ctx.Done():
	case <-t.C:
	}
}

func (p *RedisCertPurge) nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

func (p *RedisCertPurge) handleMessage(payload string) {
	var req PurgeMessage

	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		p.logger.Error("failed to parse purge message",
			zap.Error(err),
			zap.String("payload", payload))
		return
	}

	if req.Domain == "" {
		p.logger.Warn("received purge message with empty domain")
		return
	}

	p.purgeDomain(req.Domain)
}

func (p *RedisCertPurge) purgeDomain(domain string) {
	if p.certCache == nil {
		p.logger.Warn("cert cache not initialized", zap.String("domain", domain))
		return
	}

	p.certCache.RemoveManaged([]certmagic.SubjectIssuer{
		{Subject: domain},
	})

	p.logger.Info("purged certificate from in-memory cache",
		zap.String("domain", domain))
}
func parseRedisCertPurge(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	var p RedisCertPurge

	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {

			case "address":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				p.Address = d.Val()

			case "username":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				p.Username = d.Val()

			case "password":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				p.Password = d.Val()

			case "db":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				db, err := strconv.Atoi(d.Val())
				if err != nil {
					return nil, d.Errf("invalid db number: %v", err)
				}
				p.DB = db

			case "channel":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				p.Channel = d.Val()

			default:
				return nil, d.Errf("unknown subdirective: %s", d.Val())
			}
		}
	}

	return httpcaddyfile.App{
		Name:  "redis_cert_purge",
		Value: caddyconfig.JSON(p, nil),
	}, nil
}

var (
	_ caddy.Module       = (*RedisCertPurge)(nil)
	_ caddy.Provisioner  = (*RedisCertPurge)(nil)
	_ caddy.Validator    = (*RedisCertPurge)(nil)
	_ caddy.App          = (*RedisCertPurge)(nil)
	_ caddy.CleanerUpper = (*RedisCertPurge)(nil)
)
