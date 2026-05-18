package main

import "testing"

func TestFeishuCardPayloadSuccess(t *testing.T) {
	payload := feishuCardPayload(feishuInfo, "Certificate Updated", "domain=example.com")

	if got := payload["msg_type"]; got != "interactive" {
		t.Fatalf("msg_type = %v, want interactive", got)
	}

	card := payload["card"].(map[string]any)
	header := card["header"].(map[string]any)
	if got := header["template"]; got != "green" {
		t.Fatalf("header.template = %v, want green", got)
	}

	title := header["title"].(map[string]string)
	if got := title["content"]; got != "Certificate Updated" {
		t.Fatalf("title.content = %q, want Certificate Updated", got)
	}

	elements := card["elements"].([]map[string]any)
	text := elements[0]["text"].(map[string]string)
	if got := text["tag"]; got != "lark_md" {
		t.Fatalf("text.tag = %q, want lark_md", got)
	}
	if got := text["content"]; got != "domain=example.com" {
		t.Fatalf("text.content = %q, want domain=example.com", got)
	}

	noteElements := elements[2]["elements"].([]map[string]string)
	if got := noteElements[0]["content"]; got != "cloud-cert-bot" {
		t.Fatalf("note content = %q, want cloud-cert-bot", got)
	}
}

func TestFeishuCardPayloadFailure(t *testing.T) {
	payload := feishuCardPayload(feishuWarn, "Certificate Update Failed", "error=boom")

	card := payload["card"].(map[string]any)
	header := card["header"].(map[string]any)
	if got := header["template"]; got != "red" {
		t.Fatalf("header.template = %v, want red", got)
	}
}
