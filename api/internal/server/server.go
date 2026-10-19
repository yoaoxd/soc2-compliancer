package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/soc2-compliancer/app/internal/analyze"
	"github.com/soc2-compliancer/app/internal/audit"
	"github.com/soc2-compliancer/app/internal/auth"
	"github.com/soc2-compliancer/app/internal/catalog"
	"github.com/soc2-compliancer/app/internal/cirun"
	"github.com/soc2-compliancer/app/internal/config"
	"github.com/soc2-compliancer/app/internal/connections"
	"github.com/soc2-compliancer/app/internal/encrypt"
	"github.com/soc2-compliancer/app/internal/evidence"
	"github.com/soc2-compliancer/app/internal/generation"
	"github.com/soc2-compliancer/app/internal/registry"
	"github.com/soc2-compliancer/app/internal/web"
)

type Server struct {
	cfg    *config.Config
	pool   *pgxpool.Pool
	router http.Handler
	conn   *connections.Scheduler
}

func New(cfg *config.Config, pool *pgxpool.Pool) (*Server, error) {
	authRepo := auth.NewRepo(pool)
	authSvc := auth.NewService(authRepo, cfg.JWTSecret, cfg.JWTTTL).WithSSO(
		cfg.GoogleClientID, cfg.GoogleClientSecret, cfg.OAuthRedirectURL, cfg.WebappURL, cfg.AllowedDomains,
	).WithOAuthEndpoints(cfg.GoogleAuthURL, cfg.GoogleTokenURL, cfg.GoogleUserinfoURL)
	regRepo := registry.NewRepo(pool)
	regSvc := registry.NewService(regRepo)
	catSvc := catalog.NewService(cfg.TemplatesDir)
	genRepo := generation.NewRepo(pool)
	genHandler := generation.NewHandler(cfg.TemplatesDir, genRepo)
	analyzeHandler := analyze.NewHandler()

		var kek encrypt.KEK
	if cfg.EncryptionKEK != "" {
		var kmsErr error
		kek, kmsErr = encrypt.NewAWSKEK(context.Background(), encrypt.AWSKMSSetup{KeyID: cfg.EncryptionKEK})
		if kmsErr != nil {
			return nil, kmsErr
		}
	}
	cryp, err := encrypt.New(cfg.EncryptionKey, kek)
	if err != nil {
		return nil, err
	}
	connRepo := connections.NewRepo(pool)
	audRepo := audit.NewRepo(pool)
	audSvc := audit.NewService(audRepo)
	audHandler := audit.NewHandler(audSvc)
	connSvc := connections.NewService(connRepo, cryp, audSvc, cfg.MaxConnectionsPerOrg, cfg.MaxScansPerOrgPerDay)
	connHandler := connections.NewHandler(connSvc)
	connScheduler := connections.NewScheduler(connSvc, cfg.SchedulerEvery)

	evRepo := evidence.NewRepo(pool)
	evHandler := evidence.NewService(evRepo)

	ciRepo := cirun.NewRepo(pool)
	ciHandler := cirun.NewHandler(ciRepo)

	s := &Server{cfg: cfg, pool: pool, conn: connScheduler}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(60 * time.Second))

	r.Get("/api/v1/health", handleHealth)
	r.Mount("/api/v1/auth", authSvc.Routes())
	r.Mount("/api/v1/registry", regSvc.Routes())

	r.Group(func(r chi.Router) {
		r.Use(authSvc.Middleware)
		r.Mount("/api/v1/catalog", catSvc.Routes())
		r.Mount("/api/v1/analyze", analyzeHandler.Routes())
	})

	r.Group(func(r chi.Router) {
		r.Use(authSvc.Middleware, authSvc.OrgMiddleware)
		r.Mount("/api/v1/orgs/{orgID}", genHandler.Routes())
		r.Mount("/api/v1/orgs/{orgID}/connections", connHandler.Routes())
		r.Mount("/api/v1/orgs/{orgID}/evidence", evHandler.Routes())
		r.Mount("/api/v1/orgs/{orgID}/ci-runs", ciHandler.Routes())
		r.Mount("/api/v1/orgs/{orgID}/audit", audHandler.Routes())
	})

	s.router = r
	return s, nil
}

func (s *Server) Handler() http.Handler {
	return s.router
}

// StartScheduler launches the periodic re-scan loop; it stops when ctx is done.
func (s *Server) StartScheduler(ctx context.Context) {
	if s.conn != nil {
		s.conn.Start(ctx)
	}
}

func handleHealth(w http.ResponseWriter, _ *http.Request) {
	web.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
