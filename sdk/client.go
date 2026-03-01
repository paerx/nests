package sdk

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Client struct {
	BaseURL      string
	Timeout      time.Duration
	PollInterval time.Duration
	HTTP         *http.Client
}

func Init(baseURL string) *Client {
	return &Client{
		BaseURL:      strings.TrimRight(baseURL, "/"),
		Timeout:      5 * time.Minute,
		PollInterval: 2 * time.Second,
		HTTP:         &http.Client{Timeout: 15 * time.Second},
	}
}

type windowResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Wid        string `json:"wid"`
		ExpireAt   int64  `json:"expire_at"`
		CheckerWeb string `json:"checker_web"`
	} `json:"data"`
}

type checkResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Status string `json:"status"`
	} `json:"data"`
}

type plainResp struct {
	Code int    `json:"code"`
	Msg  string `json:"msg"`
	Data struct {
		Name      string `json:"name"`
		Version   int    `json:"version"`
		UpdatedAt int64  `json:"updated_at"`
		Datas     []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"datas"`
	} `json:"data"`
}

// GetConfig waits for manual confirmation and returns the value for a given key.
// It prints checker URL to stdout and blocks until ready or timeout.
func (c *Client) GetConfig(name, key string) (string, error) {
	if name == "" || key == "" {
		return "", errors.New("name and key are required")
	}
	win, err := c.createWindow(name)
	if err != nil {
		return "", err
	}
	fmt.Fprintf(os.Stdout, "Please open checker URL and confirm: %s\n", win.Data.CheckerWeb)

	deadline := time.Now().Add(c.Timeout)
	if win.Data.ExpireAt > 0 {
		expire := time.Unix(win.Data.ExpireAt, 0)
		if expire.Before(deadline) {
			deadline = expire
		}
	}

	for {
		if time.Now().After(deadline) {
			return "", errors.New("window expired or timed out")
		}
		status, err := c.checkWindow(win.Data.Wid)
		if err != nil {
			return "", err
		}
		switch status {
		case "ready":
			plain, err := c.getPlaintext(win.Data.Wid)
			if err != nil {
				return "", err
			}
			for _, kv := range plain.Data.Datas {
				if kv.Key == key {
					return kv.Value, nil
				}
			}
			return "", fmt.Errorf("key not found: %s", key)
		case "expired":
			return "", errors.New("window expired")
		default:
			time.Sleep(c.PollInterval)
		}
	}
}

func (c *Client) createWindow(name string) (*windowResp, error) {
	path := c.BaseURL + "/api/nests/server/get?name=" + url.QueryEscape(name)
	resp, err := c.HTTP.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out windowResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.Code != 0 {
		return nil, fmt.Errorf(out.Msg)
	}
	if out.Data.Wid == "" {
		return nil, errors.New("invalid wid")
	}
	return &out, nil
}

func (c *Client) checkWindow(wid string) (string, error) {
	path := c.BaseURL + "/api/nests/server/windows/check?wid=" + url.QueryEscape(wid)
	resp, err := c.HTTP.Get(path)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out checkResp
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if out.Code != 0 {
		return "", fmt.Errorf(out.Msg)
	}
	return out.Data.Status, nil
}

func (c *Client) getPlaintext(wid string) (*plainResp, error) {
	path := c.BaseURL + "/api/nests/server/plaintext?wid=" + url.QueryEscape(wid)
	resp, err := c.HTTP.Get(path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var out plainResp
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if out.Code != 0 {
		return nil, fmt.Errorf(out.Msg)
	}
	return &out, nil
}
