// Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
//
// WSO2 LLC. licenses this file to you under the Apache License,
// Version 2.0 (the "License"); you may not use this file except
// in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// Mock server that mimics the Llama Guard 3 / NeMo Guard
// OpenAI-compatible /v1/chat/completions endpoint for integration testing.
//
// Verdict logic (Llama Guard format):
//   - "simulate error" in any message → HTTP 500
//   - violence/weapons keywords        → "unsafe\nS1"
//   - sexual content keywords          → "unsafe\nS2"
//   - self-harm keywords               → "unsafe\nS6"
//   - hate speech keywords             → "unsafe\nS7"
//   - terrorism keywords               → "unsafe\nS8"
//   - everything else                  → "safe"

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ChatRequest struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
}

type ChatChoice struct {
	Message ChatMessage `json:"message"`
}

type ChatResponse struct {
	Choices []ChatChoice `json:"choices"`
}

type categoryRule struct {
	code     string
	keywords []string
}

var categoryRules = []categoryRule{
	{"S1", []string{"bomb", "weapon", "violence", "violent", "kill", "murder", "attack", "stab", "shoot", "gun"}},
	{"S2", []string{"sexual", "explicit", "nsfw", "pornograph"}},
	{"S6", []string{"suicide", "self-harm", "self harm", "cutting"}},
	{"S7", []string{"hate speech", "racist", "discrimination", "bigot", "slur"}},
	{"S8", []string{"terror", "terrorist", "bombing", "jihad"}},
}

func allMessages(msgs []ChatMessage) string {
	var sb strings.Builder
	for _, m := range msgs {
		sb.WriteString(strings.ToLower(m.Content))
		sb.WriteString(" ")
	}
	return sb.String()
}

func handleChatCompletions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	var req ChatRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON request", http.StatusBadRequest)
		return
	}

	combined := allMessages(req.Messages)

	// Simulate API error.
	if strings.Contains(combined, "simulate error") {
		http.Error(w, "Simulated NeMo Guard error", http.StatusInternalServerError)
		return
	}

	verdict := "safe"
	for _, rule := range categoryRules {
		for _, kw := range rule.keywords {
			if strings.Contains(combined, kw) {
				verdict = fmt.Sprintf("unsafe\n%s", rule.code)
				break
			}
		}
		if verdict != "safe" {
			break
		}
	}

	resp := ChatResponse{
		Choices: []ChatChoice{
			{Message: ChatMessage{Role: "assistant", Content: verdict}},
		},
	}
	json.NewEncoder(w).Encode(resp)
}

func main() {
	http.HandleFunc("/v1/chat/completions", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleChatCompletions(w, r)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Println("Mock NeMo Guard server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
