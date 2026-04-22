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

// Mock server that mimics the IBM Granite Guardian 3.3 8B
// OpenAI-compatible /v1/chat/completions endpoint for integration testing.
//
// Verdict logic:
//   - "simulate error" in user text → HTTP 500
//   - injection/jailbreak keywords   → "Yes"
//   - everything else                → "No"

package main

import (
	"encoding/json"
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

// Keywords that indicate a prompt injection or jailbreak attempt.
var injectionKeywords = []string{
	"ignore previous instructions",
	"ignore all previous",
	"disregard previous",
	"forget your instructions",
	"jailbreak",
	"bypass",
	"override instructions",
	"pretend you are",
	"act as if you have no restrictions",
	"reveal your system prompt",
	"your new instructions",
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

	// Extract the user message (last message with role "user").
	userText := ""
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if req.Messages[i].Role == "user" {
			userText = req.Messages[i].Content
			break
		}
	}

	lowerText := strings.ToLower(userText)

	// Simulate API error.
	if strings.Contains(lowerText, "simulate error") {
		http.Error(w, "Simulated Granite Guardian error", http.StatusInternalServerError)
		return
	}

	scoreWord := "no"
	for _, kw := range injectionKeywords {
		if strings.Contains(lowerText, kw) {
			scoreWord = "yes"
			break
		}
	}

	// Granite Guardian 3.3 wraps the verdict in <score> tags after a <think> block.
	content := "<think>\n</think>\n<score> " + scoreWord + " </score>"
	resp := ChatResponse{
		Choices: []ChatChoice{
			{Message: ChatMessage{Role: "assistant", Content: content}},
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

	log.Println("Mock Granite Guardian server listening on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
