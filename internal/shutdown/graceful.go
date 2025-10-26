package shutdown

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

// Handler manages graceful shutdown
type Handler struct {
	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once
	sigCh  chan os.Signal
	done   chan struct{}
}

// NewHandler creates a new shutdown handler
func NewHandler() *Handler {
	ctx, cancel := context.WithCancel(context.Background())
	return &Handler{
		ctx:    ctx,
		cancel: cancel,
		sigCh:  make(chan os.Signal, 1),
		done:   make(chan struct{}),
	}
}

// Context returns the context that will be cancelled on shutdown
func (h *Handler) Context() context.Context {
	return h.ctx
}

// Start begins listening for shutdown signals
func (h *Handler) Start() {
	signal.Notify(h.sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-h.sigCh
		slog.Info("received shutdown signal", "signal", sig)
		h.Shutdown()
	}()
}

// Stop stops listening for signals
func (h *Handler) Stop() {
	signal.Stop(h.sigCh)
	close(h.sigCh)
}

// Shutdown triggers graceful shutdown
func (h *Handler) Shutdown() {
	h.once.Do(func() {
		slog.Info("initiating graceful shutdown")
		h.cancel()
		close(h.done)
	})
}

// Wait blocks until shutdown is triggered
func (h *Handler) Wait() {
	<-h.done
}
