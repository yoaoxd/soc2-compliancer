package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTPAddr       string
	DatabaseURL    string
	JWTSecret      string
	JWTTTL         int // hours
	TemplatesDir   string
	EncryptionKey  string
	EncryptionKEK  string // optional AWS KMS key ID for envelope encryption
	SchedulerEvery time.Duration
	LogLevel       string

	MaxConnectionsPerOrg int
	MaxScansPerOrgPerDay int

	GoogleClientID     string
	GoogleClientSecret string
	OAuthRedirectURL   string
	WebappURL          string
	AllowedDomains     []string

	// Test/self-hosted endpoint overrides (default to Google's endpoints).
	GoogleAuthURL   string
	GoogleTokenURL  string
	GoogleUserinfoURL string
}

func FromEnv() *Config {
	return &Config{
		HTTPAddr:       getEnv("HTTP_ADDR", ":8080"),
		DatabaseURL:    getEnv("DATABASE_URL", "postgres://soc2:soc2@localhost:5433/soc2?sslmode=disable"),
		JWTSecret:      getEnv("JWT_SECRET", "dev-only-secret-change-me"),
		JWTTTL:         getEnvInt("JWT_TTL_HOURS", 24),
		TemplatesDir:   getEnv("TEMPLATES_DIR", "../templates"),
		EncryptionKey:  getEnv("ENCRYPTION_KEY", ""),
		EncryptionKEK:  getEnv("ENCRYPTION_KEK_ID", ""),
		SchedulerEvery: time.Duration(getEnvInt("SCHEDULER_EVERY_MINUTES", 15)) * time.Minute,
		LogLevel:       getEnv("LOG_LEVEL", "info"),

		MaxConnectionsPerOrg: getEnvInt("MAX_CONNECTIONS_PER_ORG", 10),
		MaxScansPerOrgPerDay: getEnvInt("MAX_SCANS_PER_ORG_PER_DAY", 100),

		GoogleClientID:     getEnv("GOOGLE_CLIENT_ID", ""),
		GoogleClientSecret: getEnv("GOOGLE_CLIENT_SECRET", ""),
		OAuthRedirectURL:   getEnv("OAUTH_REDIRECT_URL", "http://localhost:8080/api/v1/auth/google/callback"),
		WebappURL:          getEnv("WEBAPP_URL", "http://localhost:5173"),
		AllowedDomains:     getEnvList("OAUTH_ALLOWED_DOMAINS", "gmail.com"),

		GoogleAuthURL:      getEnv("GOOGLE_AUTH_URL", "https://accounts.google.com/o/oauth2/auth"),
		GoogleTokenURL:     getEnv("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token"),
		GoogleUserinfoURL:  getEnv("GOOGLE_USERINFO_URL", "https://www.googleapis.com/oauth2/v2/userinfo"),
	}
}

func getEnvList(key, fallback string) []string {
	v := getEnv(key, "")
	if v == "" {
		return []string{fallback}
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
	}
	return fallback
}
