package llm

import (
	"testing"
)

func TestRequest_GetAllContent(t *testing.T) {
	req := &Request{
		SystemPrompt: "You are a helpful assistant.",
		Messages: []Message{
			{Role: RoleUser, Content: "Hello, how are you?"},
			{Role: RoleAssistant, Content: "I'm doing well, thanks!"},
			{Role: RoleUser, Content: "Can you help me?"},
		},
		Prompt: "Additional prompt text",
	}

	content := req.GetAllContent()

	// Should contain all content
	if content == "" {
		t.Error("Expected non-empty content")
	}

	// Should contain system prompt
	if !containsString(content, "helpful assistant") {
		t.Error("Expected system prompt in content")
	}

	// Should contain messages
	if !containsString(content, "Hello, how are you") {
		t.Error("Expected user message in content")
	}

	// Should contain prompt
	if !containsString(content, "Additional prompt") {
		t.Error("Expected prompt in content")
	}
}

func TestRequest_GetContentSummary(t *testing.T) {
	req := &Request{
		SystemPrompt: "You are a helpful assistant.",
		Messages: []Message{
			{Role: RoleUser, Content: "Hello"},
			{Role: RoleAssistant, Content: "Hi there"},
		},
		Tools: []Tool{
			{Type: "function", Function: ToolFunction{Name: "search"}},
		},
		Attachments: []Attachment{
			{Type: "image", Name: "photo.jpg"},
			{Type: "file", Name: "doc.pdf"},
		},
	}

	summary := req.GetContentSummary()

	if summary.MessageCount != 2 {
		t.Errorf("MessageCount = %d, want 2", summary.MessageCount)
	}

	if !summary.HasSystemPrompt {
		t.Error("Expected HasSystemPrompt to be true")
	}

	if !summary.HasTools {
		t.Error("Expected HasTools to be true")
	}

	if !summary.HasAttachments {
		t.Error("Expected HasAttachments to be true")
	}

	if len(summary.AttachmentTypes) != 2 {
		t.Errorf("AttachmentTypes length = %d, want 2", len(summary.AttachmentTypes))
	}
}

func TestRequest_GetContentSummary_Empty(t *testing.T) {
	req := &Request{}

	summary := req.GetContentSummary()

	if summary.MessageCount != 0 {
		t.Errorf("MessageCount = %d, want 0", summary.MessageCount)
	}

	if summary.HasSystemPrompt {
		t.Error("Expected HasSystemPrompt to be false")
	}

	if summary.HasTools {
		t.Error("Expected HasTools to be false")
	}

	if summary.HasAttachments {
		t.Error("Expected HasAttachments to be false")
	}
}

func TestProviderConstants(t *testing.T) {
	providers := []Provider{
		ProviderOpenAI,
		ProviderAnthropic,
		ProviderAzure,
		ProviderGoogle,
		ProviderOllama,
		ProviderUnknown,
	}

	for _, p := range providers {
		if p == "" {
			t.Error("Provider constant should not be empty")
		}
	}
}

func TestRequestTypeConstants(t *testing.T) {
	types := []RequestType{
		RequestTypeChat,
		RequestTypeCompletion,
		RequestTypeEmbedding,
		RequestTypeImage,
		RequestTypeAudio,
		RequestTypeFile,
		RequestTypeUnknown,
	}

	for _, rt := range types {
		if rt == "" {
			t.Error("RequestType constant should not be empty")
		}
	}
}

func TestRoleConstants(t *testing.T) {
	roles := []Role{
		RoleSystem,
		RoleUser,
		RoleAssistant,
		RoleTool,
		RoleFunction,
	}

	for _, r := range roles {
		if r == "" {
			t.Error("Role constant should not be empty")
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
