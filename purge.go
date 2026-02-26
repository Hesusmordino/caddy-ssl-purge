package caddycachepurge

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	_ "unsafe"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/certmagic"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"time"
)

func init() {
	caddy.RegisterModule(RedisCertPurge{})
	httpcaddyfile.RegisterGlobalOption("redis_cert_purge", parseRedisCertPurge)
}

var caddyCertCache *certmagic.Cache

type RedisCertPurge struct {
	Address  string `json:"address,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	DB       int    `json:"db,omitempty"`
	Channel  string `json:"channel,omitempty"`

	logger *zap.Logger
	client *redis.Client
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
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

    caddyCertCache = certmagic.Default.Cache

    return nil
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
		zap.String("channel", p.Channel))

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

	p.logger.Info("purged certificate from cache",
		zap.String("domain", req.Domain))
}

func (p *RedisCertPurge) purgeDomain(domain string) {
	caddyCertCache.RemoveManaged([]certmagic.SubjectIssuer{
		{Subject: domain},
	})
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

			case "password":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				p.Password = d.Val()

			case "username":
				if !d.NextArg() {
					return nil, d.ArgErr()
				}
				p.Username = d.Val()	

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
