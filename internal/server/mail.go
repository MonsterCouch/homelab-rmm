package server

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// MailSettings is stored under settings key "smtp".
type MailSettings struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username"`
	Password string   `json:"password"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	TLSMode  string   `json:"tls"` // "starttls" (587), "tls" (465), "none"
	Enabled  bool     `json:"enabled"`
}

type mailer struct {
	db *DB
}

func newMailer(db *DB) *mailer { return &mailer{db: db} }

func (m *mailer) settings() MailSettings {
	var ms MailSettings
	m.db.SettingJSON("smtp", &ms)
	if ms.Port == 0 {
		ms.Port = 587
	}
	if ms.TLSMode == "" {
		ms.TLSMode = "starttls"
	}
	return ms
}

// Send delivers a plain-text message to the configured recipients. It uses
// the standard library so the server has no mail dependency; implicit TLS,
// STARTTLS and plain are all supported because home-lab relays vary.
func (m *mailer) Send(subject, body string) error {
	ms := m.settings()
	if !ms.Enabled {
		return errors.New("email is not enabled in settings")
	}
	return sendMail(ms, subject, body)
}

func sendMail(ms MailSettings, subject, body string) error {
	if ms.Host == "" || len(ms.To) == 0 || ms.From == "" {
		return errors.New("smtp host, from and at least one recipient are required")
	}
	addr := net.JoinHostPort(ms.Host, fmt.Sprint(ms.Port))
	var (
		c   *smtp.Client
		err error
	)
	dialer := net.Dialer{Timeout: 15 * time.Second}
	tlsCfg := &tls.Config{ServerName: ms.Host, MinVersion: tls.VersionTLS12}
	switch ms.TLSMode {
	case "tls":
		conn, derr := tls.DialWithDialer(&dialer, "tcp", addr, tlsCfg)
		if derr != nil {
			return derr
		}
		c, err = smtp.NewClient(conn, ms.Host)
	default:
		conn, derr := dialer.Dial("tcp", addr)
		if derr != nil {
			return derr
		}
		c, err = smtp.NewClient(conn, ms.Host)
		if err == nil && ms.TLSMode == "starttls" {
			if ok, _ := c.Extension("STARTTLS"); ok {
				err = c.StartTLS(tlsCfg)
			} else {
				err = errors.New("server does not offer STARTTLS")
			}
		}
	}
	if err != nil {
		return err
	}
	defer c.Close()
	if ms.Username != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(smtp.PlainAuth("", ms.Username, ms.Password, ms.Host)); err != nil {
				return fmt.Errorf("smtp auth: %w", err)
			}
		}
	}
	if err := c.Mail(ms.From); err != nil {
		return err
	}
	for _, to := range ms.To {
		if err := c.Rcpt(strings.TrimSpace(to)); err != nil {
			return err
		}
	}
	wc, err := c.Data()
	if err != nil {
		return err
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n%s\r\n",
		ms.From, strings.Join(ms.To, ", "), subject, time.Now().Format(time.RFC1123Z), body)
	if _, err := wc.Write([]byte(msg)); err != nil {
		return err
	}
	if err := wc.Close(); err != nil {
		return err
	}
	return c.Quit()
}
