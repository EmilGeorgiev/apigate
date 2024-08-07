package main

import (
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

// EchoRequest represents the structure of the echo response
type EchoRequest struct {
	URL            string              `json:"url"`
	Headers        map[string][]string `json:"headers"`
	RequestPayload []byte              `json:"request_payload"`
}

func main() {
	// Define the HTTP handler
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Read the request payload
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read request body", http.StatusBadRequest)
			return
		}

		// Extract headers
		//headers := make(map[string]interface{})
		//for key, values := range r.Header {
		//	if len(values) > 1 {
		//		headers[key] = values
		//	} else {
		//		headers[key] = values[0]
		//	}
		//}

		// Populate the EchoRequest struct
		echoResponse := EchoRequest{
			URL:            r.URL.String(),
			Headers:        r.Header,
			RequestPayload: body,
		}

		// Marshal the struct to JSON
		responseBytes, err := json.Marshal(echoResponse)
		if err != nil {
			http.Error(w, "Unable to marshal JSON", http.StatusInternalServerError)
			return
		}

		// Set the content type to application/json
		w.Header().Set("Content-Type", "application/json")

		// Write the JSON response
		w.Write(responseBytes)
	})

	// Start the server
	port := "8080"
	log.Printf("Starting echo server on port %s", port)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
