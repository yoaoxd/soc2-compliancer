package connections

import (
	"context"
	"log"
	"time"
)

// Scheduler periodically runs ScanDue in the background.
type Scheduler struct {
	svc     *Service
	every   time.Duration
	timeout time.Duration
}

func NewScheduler(svc *Service, every time.Duration) *Scheduler {
	return &Scheduler{svc: svc, every: every, timeout: 5 * time.Minute}
}

// Start launches the background loop; it stops when ctx is cancelled.
func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(s.every)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				runCtx, cancel := context.WithTimeout(ctx, s.timeout)
				n, err := s.svc.ScanDue(runCtx)
				cancel()
				if err != nil {
					log.Printf("scheduler: scan due: %v", err)
					continue
				}
				if n > 0 {
					log.Printf("scheduler: kicked off %d due scans", n)
				}
			}
		}
	}()
}
