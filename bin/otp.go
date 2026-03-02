package bin

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	qrcode "github.com/skip2/go-qrcode"
)

type OTPInfo struct {
	Secret string
	URI    string
	QRBase string
}

func generateOTP(name string) (*OTPInfo, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Nests",
		AccountName: "Nests:" + name,
		Period:      30,
		Digits:      otp.DigitsSix,
	})
	if err != nil {
		return nil, err
	}
	uri := key.URL()
	qr, err := qrcode.Encode(uri, qrcode.Medium, 240)
	if err != nil {
		return nil, err
	}
	return &OTPInfo{
		Secret: key.Secret(),
		URI:    uri,
		QRBase: base64.StdEncoding.EncodeToString(qr),
	}, nil
}

func (s *Store) VerifyOTP(name, code string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cfgs, err := s.loadConfigs()
	if err != nil {
		return false, err
	}
	for _, cfg := range cfgs.Configs {
		if cfg.Name == name {
			if cfg.OtpSecret == "" {
				return false, errors.New("otp not initialized")
			}
			ok, err := totp.ValidateCustom(code, cfg.OtpSecret, time.Now(), totp.ValidateOpts{
				Period:    30,
				Skew:      1,
				Digits:    otp.DigitsSix,
				Algorithm: otp.AlgorithmSHA1,
			})
			if err != nil {
				return false, err
			}
			return ok, nil
		}
	}
	return false, errors.New("config not found")
}
