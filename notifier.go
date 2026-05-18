package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Notifier interface {
	Success(title, content string)
	Failure(title, content string)
}

type logOnlyNotifier struct{}

type feishuNotifier struct {
	url        string
	httpClient *http.Client
}

type feishuMessageKind string

const (
	feishuInfo feishuMessageKind = "info"
	feishuWarn feishuMessageKind = "warn"
)

func NewNotifier(notifyURL string) Notifier {
	if strings.TrimSpace(notifyURL) == "" {
		return &logOnlyNotifier{}
	}
	return &feishuNotifier{
		url: notifyURL,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (n *logOnlyNotifier) Success(title, content string) {
	zap.L().Info(title, zap.String("content", content))
}

func (n *logOnlyNotifier) Failure(title, content string) {
	zap.L().Error(title, zap.String("content", content))
}

func (n *feishuNotifier) Success(title, content string) {
	if err := n.send(feishuInfo, title, content); err != nil {
		zap.L().Error("send success notification failed", zap.Error(err))
	}
}

func (n *feishuNotifier) Failure(title, content string) {
	if err := n.send(feishuWarn, title, content); err != nil {
		zap.L().Error("send failure notification failed", zap.Error(err))
	}
}

func (n *feishuNotifier) send(kind feishuMessageKind, title, content string) error {
	body, err := json.Marshal(feishuCardPayload(kind, title, content))
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPost, n.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := n.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		responseBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status: %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func feishuCardPayload(kind feishuMessageKind, title, content string) map[string]any {
	template := "green"
	if kind == feishuWarn {
		template = "red"
	}

	return map[string]any{
		"msg_type": "interactive",
		"card": map[string]any{
			"header": map[string]any{
				"title": map[string]string{
					"tag":     "plain_text",
					"content": title,
				},
				"template": template,
			},
			"elements": []map[string]any{
				{
					"tag": "div",
					"text": map[string]string{
						"tag":     "lark_md",
						"content": content,
					},
				},
				{
					"tag": "hr",
				},
				{
					"tag": "note",
					"elements": []map[string]string{
						{
							"tag":     "lark_md",
							"content": "cloud-cert-bot",
						},
					},
				},
			},
		},
	}
}
