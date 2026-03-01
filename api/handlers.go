package api

import (
	"net"
	"net/http"
	"net/url"

	"github.com/gin-gonic/gin"

	"nests/bin"
)

type updateConfigRequest struct {
	Name    string      `json:"name"`
	KdfSalt string      `json:"kdf_salt"`
	Sign    string      `json:"sign"`
	EDatas  []bin.EData `json:"e_datas"`
}

type addConfigRequest struct {
	Name    string `json:"name"`
	EKey    string `json:"e-key"`
	EValue  string `json:"e-value"`
	Sign    string `json:"sign"`
	KdfSalt string `json:"kdf_salt"`
}

type windowWriteRequest struct {
	Wid              string `json:"wid"`
	EncryptedTempKey string `json:"encrypted_temp_key"`
	EnvKey           string `json:"env_key"`
}

func RegisterRoutes(r *gin.Engine, store *bin.Store, checkerBase string) {
	api := r.Group("/api/nests")

	api.GET("/config/list", func(c *gin.Context) {
		list, err := store.ListConfigs()
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		respondOK(c, list)
	})

	api.GET("/config/get", func(c *gin.Context) {
		name := c.Query("name")
		if name == "" {
			respondError(c, http.StatusBadRequest, "name is required")
			return
		}

		cfg, err := store.GetConfig(name)
		if err != nil {
			respondError(c, http.StatusNotFound, err.Error())
			return
		}

		respondOK(c, cfg)
	})

	api.POST("/config/update", func(c *gin.Context) {
		if !store.AllowUpdate(c.ClientIP()) {
			respondError(c, http.StatusTooManyRequests, "rate limit")
			return
		}

		var req updateConfigRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondError(c, http.StatusBadRequest, "invalid body")
			return
		}
		if req.Name == "" {
			respondError(c, http.StatusBadRequest, "name is required")
			return
		}
		if req.Sign == "" {
			respondError(c, http.StatusBadRequest, "sign is required")
			return
		}

		cfg, err := store.UpdateConfig(req.Name, req.KdfSalt, req.Sign, req.EDatas, c.ClientIP())
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		respondOK(c, cfg)
	})

	api.POST("/config/add", func(c *gin.Context) {
		if !store.AllowUpdate(c.ClientIP()) {
			respondError(c, http.StatusTooManyRequests, "rate limit")
			return
		}

		var req addConfigRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondError(c, http.StatusBadRequest, "invalid body")
			return
		}
		if req.Name == "" || req.EKey == "" || req.EValue == "" {
			respondError(c, http.StatusBadRequest, "name, e-key, e-value are required")
			return
		}

		cfg, err := store.AddConfigEntry(req.Name, req.EKey, req.EValue, req.Sign, req.KdfSalt, c.ClientIP())
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		respondOK(c, cfg)
	})

	api.GET("/server/get", func(c *gin.Context) {
		if !store.AllowIP(c.ClientIP()) {
			respondError(c, http.StatusTooManyRequests, "rate limit")
			return
		}

		name := c.Query("name")
		if name == "" {
			respondError(c, http.StatusBadRequest, "name is required")
			return
		}

		win, err := store.CreateWindow(name, c.ClientIP())
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}

		respondOK(c, gin.H{
			"wid":         win.Wid,
			"expire_at":   win.ExpireAt,
			"checker_web": checkerBase + "?wid=" + win.Wid + "&name=" + url.QueryEscape(win.Name),
		})
	})

	api.POST("/server/windows", func(c *gin.Context) {
		var req windowWriteRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			respondError(c, http.StatusBadRequest, "invalid body")
			return
		}
		if req.Wid == "" || req.EncryptedTempKey == "" {
			respondError(c, http.StatusBadRequest, "wid and encrypted_temp_key are required")
			return
		}
		if !store.AllowWindow(req.Wid) {
			respondError(c, http.StatusTooManyRequests, "rate limit")
			return
		}

		if err := store.SetWindowTempKey(req.Wid, req.EncryptedTempKey, c.ClientIP()); err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		if req.EnvKey != "" {
			if err := store.SetWindowEnvKey(req.Wid, req.EnvKey, c.ClientIP()); err != nil {
				respondError(c, http.StatusBadRequest, err.Error())
				return
			}
		}
		respondOK(c, gin.H{"status": "ready"})
	})

	api.GET("/server/windows/check", func(c *gin.Context) {
		wid := c.Query("wid")
		if wid == "" {
			respondError(c, http.StatusBadRequest, "wid is required")
			return
		}
		if !store.AllowWindow(wid) {
			respondError(c, http.StatusTooManyRequests, "rate limit")
			return
		}

		status, key, err := store.CheckWindow(wid, c.ClientIP())
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}

		resp := gin.H{"status": status}
		if key != "" {
			resp["encrypted_temp_key"] = key
		}
		respondOK(c, resp)
	})

	api.GET("/server/plaintext", func(c *gin.Context) {
		if !isPrivateIP(c.ClientIP()) {
			respondError(c, http.StatusForbidden, "internal only")
			return
		}
		wid := c.Query("wid")
		if wid == "" {
			respondError(c, http.StatusBadRequest, "wid is required")
			return
		}

		data, err := store.PlaintextByWindow(wid, c.ClientIP())
		if err != nil {
			respondError(c, http.StatusBadRequest, err.Error())
			return
		}
		respondOK(c, data)
	})
}

func respondOK(c *gin.Context, data any) {
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": data})
}

func respondError(c *gin.Context, status int, msg string) {
	c.JSON(status, gin.H{"code": 1, "msg": msg})
}

func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	default:
		return false
	}
}
