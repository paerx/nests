package bin

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Store struct {
	dataDir     string
	configsPath string
	windowsPath string
	auditPath   string
	backupDir   string
	windowEnv   map[string]string
	windowCalls map[string]int
	mu          sync.Mutex
	limiter     *RateLimiter
}

func NewStore(dataDir string) *Store {
	return &Store{
		dataDir:     dataDir,
		configsPath: filepath.Join(dataDir, "configs.json"),
		windowsPath: filepath.Join(dataDir, "windows.json"),
		auditPath:   filepath.Join(dataDir, "audit.log"),
		backupDir:   filepath.Join(dataDir, "backup"),
		windowEnv:   map[string]string{},
		windowCalls: map[string]int{},
		limiter:     NewRateLimiter(),
	}
}

func (s *Store) Init() error {
	if err := os.MkdirAll(s.dataDir, 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(s.backupDir, 0o755); err != nil {
		return err
	}
	if err := ensureFile(s.configsPath, defaultConfigs()); err != nil {
		return err
	}
	if err := ensureFile(s.windowsPath, defaultWindows()); err != nil {
		return err
	}
	if _, err := os.Stat(s.auditPath); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(s.auditPath, []byte(""), 0o644); err != nil {
			return err
		}
	}
	return nil
}

func ensureFile(path string, v any) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else {
		if !os.IsNotExist(err) {
			return err
		}
	}
	return writeJSONAtomic(path, v)
}

type ConfigFile struct {
	Meta    Meta     `json:"meta"`
	Configs []Config `json:"configs"`
}

type Meta struct {
	SchemaVersion int   `json:"schema_version"`
	CreatedAt     int64 `json:"created_at"`
	UpdatedAt     int64 `json:"updated_at"`
}

type Config struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Version   int     `json:"version"`
	KdfSalt   string  `json:"kdf_salt"`
	Sign      string  `json:"sign"`
	OtpSecret string  `json:"otp_secret,omitempty"`
	CreatedAt int64   `json:"created_at"`
	UpdatedAt int64   `json:"updated_at"`
	EDatas    []EData `json:"e_datas"`
}

type ConfigSummary struct {
	Name      string `json:"name"`
	Version   int    `json:"version"`
	UpdatedAt int64  `json:"updated_at"`
}

type EData struct {
	ID        string `json:"id"`
	EKey      string `json:"e_key"`
	EValue    string `json:"e_value"`
	CreatedAt int64  `json:"created_at"`
	UpdatedAt int64  `json:"updated_at"`
}

type WindowsFile struct {
	Windows []Window `json:"windows"`
}

type Window struct {
	Wid              string  `json:"wid"`
	Name             string  `json:"name"`
	CreatedAt        int64   `json:"created_at"`
	ExpireAt         int64   `json:"expire_at"`
	Used             bool    `json:"used"`
	RetryCount       int     `json:"retry_count"`
	MaxRetry         int     `json:"max_retry"`
	EncryptedTempKey *string `json:"encrypted_temp_key"`
}

func (s *Store) GetConfig(name string) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgs, err := s.loadConfigs()
	if err != nil {
		return Config{}, err
	}
	for _, cfg := range cfgs.Configs {
		if cfg.Name == name {
			return cfg, nil
		}
	}
	return Config{}, fmt.Errorf("config not found")
}

func (s *Store) ListConfigs() ([]ConfigSummary, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgs, err := s.loadConfigs()
	if err != nil {
		return nil, err
	}

	out := make([]ConfigSummary, 0, len(cfgs.Configs))
	for _, cfg := range cfgs.Configs {
		out = append(out, ConfigSummary{
			Name:      cfg.Name,
			Version:   cfg.Version,
			UpdatedAt: cfg.UpdatedAt,
		})
	}
	return out, nil
}

func (s *Store) UpdateConfig(name, kdfSalt, sign string, eDatas []EData, ip string) (Config, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgs, err := s.loadConfigs()
	if err != nil {
		return Config{}, err
	}

	now := time.Now().Unix()
	for i, cfg := range cfgs.Configs {
		if cfg.Name == name {
			if err := s.backupConfig(cfg); err != nil {
				return Config{}, err
			}

			cfg.Version++
			cfg.Sign = sign
			if kdfSalt != "" {
				cfg.KdfSalt = kdfSalt
			}
			cfg.UpdatedAt = now
			cfg.EDatas = fillEDataTimestamps(cfg.EDatas, eDatas, now)
			cfgs.Configs[i] = cfg
			cfgs.Meta.UpdatedAt = now
			if err := writeJSONAtomic(s.configsPath, cfgs); err != nil {
				return Config{}, err
			}
			s.appendAudit(ip, "config_update", name, "success", fmt.Sprintf("version %d -> %d", cfg.Version-1, cfg.Version))
			return cfg, nil
		}
	}

	return Config{}, fmt.Errorf("config not found")
}

func (s *Store) AddConfigEntry(name, eKey, eValue, sign, kdfSalt, ip string) (Config, *OTPInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgs, err := s.loadConfigs()
	if err != nil {
		return Config{}, nil, err
	}

	now := time.Now().Unix()
	for i, cfg := range cfgs.Configs {
		if cfg.Name != name {
			continue
		}

		if err := s.backupConfig(cfg); err != nil {
			return Config{}, nil, err
		}

		cfg.Version++
		if sign != "" {
			cfg.Sign = sign
		}
		cfg.UpdatedAt = now
		cfg.EDatas = append(cfg.EDatas, EData{
			ID:        randID(12),
			EKey:      eKey,
			EValue:    eValue,
			CreatedAt: now,
			UpdatedAt: now,
		})
		cfgs.Configs[i] = cfg
		cfgs.Meta.UpdatedAt = now
		if err := writeJSONAtomic(s.configsPath, cfgs); err != nil {
			return Config{}, nil, err
		}
		s.appendAudit(ip, "config_add", name, "success", fmt.Sprintf("version -> %d", cfg.Version))
		return cfg, nil, nil
	}

	if kdfSalt == "" {
		return Config{}, nil, errors.New("kdf_salt is required for new config")
	}

	if cfgs.Meta.CreatedAt == 0 {
		cfgs.Meta.CreatedAt = now
	}

	otpInfo, err := generateOTP(name)
	if err != nil {
		return Config{}, nil, err
	}

	newCfg := Config{
		ID:        randID(16),
		Name:      name,
		Version:   1,
		KdfSalt:   kdfSalt,
		Sign:      sign,
		OtpSecret: otpInfo.Secret,
		CreatedAt: now,
		UpdatedAt: now,
		EDatas: []EData{{
			ID:        randID(12),
			EKey:      eKey,
			EValue:    eValue,
			CreatedAt: now,
			UpdatedAt: now,
		}},
	}
	cfgs.Configs = append(cfgs.Configs, newCfg)
	cfgs.Meta.UpdatedAt = now
	if err := writeJSONAtomic(s.configsPath, cfgs); err != nil {
		return Config{}, nil, err
	}
	s.appendAudit(ip, "config_add", name, "success", "version 0 -> 1")
	return newCfg, otpInfo, nil
}

func (s *Store) CreateWindow(name, ip string) (Window, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	windows, err := s.loadWindows()
	if err != nil {
		return Window{}, err
	}

	now := time.Now().Unix()
	windows.Windows = filterExpiredWindows(windows.Windows, now)

	win := Window{
		Wid:        randToken(16),
		Name:       name,
		CreatedAt:  now,
		ExpireAt:   now + 300,
		Used:       false,
		RetryCount: 0,
		MaxRetry:   3,
	}
	windows.Windows = append(windows.Windows, win)
	if err := writeJSONAtomic(s.windowsPath, windows); err != nil {
		return Window{}, err
	}
	return win, nil
}

func (s *Store) SetWindowTempKey(wid, key, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	windows, err := s.loadWindows()
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	windows.Windows = filterExpiredWindows(windows.Windows, now)

	for i, w := range windows.Windows {
		if w.Wid == wid {
			if w.ExpireAt <= now {
				return errors.New("window expired")
			}
			if w.Used {
				return errors.New("window used")
			}
			if w.EncryptedTempKey == nil {
				w.EncryptedTempKey = &key
			}
			windows.Windows[i] = w
			if err := writeJSONAtomic(s.windowsPath, windows); err != nil {
				return err
			}
			s.appendAudit(ip, "window_ready", w.Name, "success", fmt.Sprintf("wid %s", wid))
			return nil
		}
	}
	return errors.New("window not found")
}

func (s *Store) SetWindowEnvKey(wid, key, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	windows, err := s.loadWindows()
	if err != nil {
		return err
	}

	now := time.Now().Unix()
	windows.Windows = filterExpiredWindows(windows.Windows, now)

	for _, w := range windows.Windows {
		if w.Wid == wid {
			if w.ExpireAt <= now {
				return errors.New("window expired")
			}
			if w.Used {
				return errors.New("window used")
			}
			s.windowEnv[wid] = key
			s.windowCalls[wid] = 0
			return nil
		}
	}
	return errors.New("window not found")
}

func (s *Store) CheckWindow(wid, ip string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	windows, err := s.loadWindows()
	if err != nil {
		return "", "", err
	}

	now := time.Now().Unix()

	for i, w := range windows.Windows {
		if w.Wid == wid {
			if w.ExpireAt <= now {
				delete(s.windowEnv, wid)
				delete(s.windowCalls, wid)
				return "expired", "", nil
			}
			if w.Used {
				delete(s.windowEnv, wid)
				delete(s.windowCalls, wid)
				return "expired", "", nil
			}
			if w.EncryptedTempKey == nil {
				return "waiting", "", nil
			}

			key := *w.EncryptedTempKey
			if _, ok := s.windowEnv[wid]; ok {
				return "ready", key, nil
			}

			w.Used = true
			windows.Windows[i] = w
			if err := writeJSONAtomic(s.windowsPath, windows); err != nil {
				return "", "", err
			}
			delete(s.windowEnv, wid)
			delete(s.windowCalls, wid)
			s.appendAudit(ip, "window_check", w.Name, "success", fmt.Sprintf("wid %s", wid))
			return "ready", key, nil
		}
	}
	return "", "", errors.New("window not found")
}

func (s *Store) PlaintextByWindow(wid, ip string) (map[string]any, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	windows, err := s.loadWindows()
	if err != nil {
		return nil, err
	}

	now := time.Now().Unix()
	windows.Windows = filterExpiredWindows(windows.Windows, now)

	var win *Window
	var idx int
	for i, w := range windows.Windows {
		if w.Wid == wid {
			win = &w
			idx = i
			break
		}
	}
	if win == nil {
		return nil, errors.New("window not found")
	}
	if win.ExpireAt <= now || win.Used {
		delete(s.windowEnv, wid)
		delete(s.windowCalls, wid)
		return nil, errors.New("window expired")
	}

	calls := s.windowCalls[wid]
	calls++
	s.windowCalls[wid] = calls

	cfg, err := s.getConfigLocked(win.Name)
	if err != nil {
		if calls >= 2 {
			win.Used = true
			windows.Windows[idx] = *win
			_ = writeJSONAtomic(s.windowsPath, windows)
			delete(s.windowEnv, wid)
			delete(s.windowCalls, wid)
		}
		return nil, err
	}

	if env, ok := s.windowEnv[wid]; ok && env != "" {
		plain, err := DecryptConfigWithEnvKey(cfg, env)
		if err != nil {
			if calls >= 2 {
				win.Used = true
				windows.Windows[idx] = *win
				_ = writeJSONAtomic(s.windowsPath, windows)
				delete(s.windowEnv, wid)
				delete(s.windowCalls, wid)
			}
			return nil, err
		}
		win.Used = true
		windows.Windows[idx] = *win
		_ = writeJSONAtomic(s.windowsPath, windows)
		delete(s.windowEnv, wid)
		delete(s.windowCalls, wid)
		s.appendAudit(ip, "window_plaintext", win.Name, "success", fmt.Sprintf("wid %s call %d", wid, calls))
		return map[string]any{
			"name":       cfg.Name,
			"version":    cfg.Version,
			"updated_at": cfg.UpdatedAt,
			"datas":      plain,
		}, nil
	}

	return nil, errors.New("env key not confirmed")
}

func (s *Store) getConfigLocked(name string) (Config, error) {
	cfgs, err := s.loadConfigs()
	if err != nil {
		return Config{}, err
	}
	for _, cfg := range cfgs.Configs {
		if cfg.Name == name {
			return cfg, nil
		}
	}
	return Config{}, fmt.Errorf("config not found")
}

func (s *Store) AllowIP(ip string) bool {
	return s.limiter.Allow("ip:"+ip, 60)
}

func (s *Store) AllowWindow(wid string) bool {
	return s.limiter.Allow("wid:"+wid, 60)
}

func (s *Store) AllowUpdate(ip string) bool {
	return s.limiter.Allow("update:"+ip, 65)
}

func (s *Store) AllowOTP(ip string) bool {
	return s.limiter.Allow("otp:"+ip, 10)
}

func (s *Store) loadConfigs() (ConfigFile, error) {
	var cfgs ConfigFile
	b, err := os.ReadFile(s.configsPath)
	if err != nil {
		return cfgs, err
	}
	if len(b) == 0 {
		cfgs = defaultConfigs().(ConfigFile)
		return cfgs, nil
	}
	if err := json.Unmarshal(b, &cfgs); err != nil {
		return cfgs, err
	}
	return cfgs, nil
}

func (s *Store) loadWindows() (WindowsFile, error) {
	var wins WindowsFile
	b, err := os.ReadFile(s.windowsPath)
	if err != nil {
		return wins, err
	}
	if len(b) == 0 {
		wins = defaultWindows().(WindowsFile)
		return wins, nil
	}
	if err := json.Unmarshal(b, &wins); err != nil {
		return wins, err
	}
	return wins, nil
}

func defaultConfigs() any {
	now := time.Now().Unix()
	return ConfigFile{
		Meta:    Meta{SchemaVersion: 1, CreatedAt: now, UpdatedAt: now},
		Configs: []Config{},
	}
}

func defaultWindows() any {
	return WindowsFile{Windows: []Window{}}
}

func fillEDataTimestamps(prev, next []EData, now int64) []EData {
	if len(next) == 0 {
		return []EData{}
	}
	prevByID := map[string]EData{}
	for _, e := range prev {
		prevByID[e.ID] = e
	}

	out := make([]EData, 0, len(next))
	for _, e := range next {
		if e.ID == "" {
			e.ID = randID(12)
		}
		if old, ok := prevByID[e.ID]; ok {
			e.CreatedAt = old.CreatedAt
			if e.UpdatedAt == 0 {
				e.UpdatedAt = now
			}
		} else {
			if e.CreatedAt == 0 {
				e.CreatedAt = now
			}
			if e.UpdatedAt == 0 {
				e.UpdatedAt = now
			}
		}
		out = append(out, e)
	}
	return out
}

func filterActiveWindows(wins []Window, now int64) []Window {
	return filterExpiredWindows(wins, now)
}

func filterExpiredWindows(wins []Window, now int64) []Window {
	out := make([]Window, 0, len(wins))
	for _, w := range wins {
		if w.ExpireAt <= now {
			continue
		}
		out = append(out, w)
	}
	return out
}

func randID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randToken(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	_, _ = rand.Read(b)
	for i := range b {
		b[i] = letters[int(b[i])%len(letters)]
	}
	return string(b)
}

func writeJSONAtomic(path string, v any) error {
	tmp := path + ".tmp." + randID(4)
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	dir := filepath.Dir(path)
	if df, err := os.Open(dir); err == nil {
		_ = df.Sync()
		_ = df.Close()
	}
	return nil
}

func (s *Store) appendAudit(ip, action, name, result, detail string) {
	entry := map[string]any{
		"time":   time.Now().Unix(),
		"ip":     ip,
		"action": action,
		"name":   name,
		"wid":    nil,
		"result": result,
		"detail": detail,
	}
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	f, err := os.OpenFile(s.auditPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	_, _ = f.Write(append(b, '\n'))
	_ = f.Close()
}

func (s *Store) backupConfig(cfg Config) error {
	ts := time.Now().Unix()
	filename := fmt.Sprintf("%s_v%d_%d.json", cfg.Name, cfg.Version, ts)
	path := filepath.Join(s.backupDir, filename)
	return writeJSONAtomic(path, cfg)
}

type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	count int
	start time.Time
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{buckets: map[string]*bucket{}}
}

func (l *RateLimiter) Allow(key string, maxPerMinute int) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	b, ok := l.buckets[key]
	if !ok {
		l.buckets[key] = &bucket{count: 1, start: now}
		return true
	}
	if now.Sub(b.start) > time.Minute {
		b.start = now
		b.count = 1
		return true
	}
	if b.count >= maxPerMinute {
		return false
	}
	b.count++
	return true
}
