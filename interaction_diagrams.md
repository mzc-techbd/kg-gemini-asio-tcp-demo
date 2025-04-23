# Project Interaction Diagrams

## 1. Overall Interaction Flow

This diagram shows the complete sequence of interactions between the TCP Client, TCP Server, Google Authentication Service, and the Gemini API.

```mermaid
sequenceDiagram
    participant C as TCP Client
    participant S as TCP Server
    participant GA as Google Auth Service
    participant GAPI as Gemini API

    C->>+S: Connect(host, port)
    S-->>-C: Connection Established

    loop For each request (epoch)
        C->>S: Send Korean Sentence (e.g., from korean_sentences.txt)

        %% Server-side processing %%
        Note over S: Receive message, start processing (Session::read -> Session::process_message)

        alt Token needs refresh or is invalid
            S->>+GA: Request Access Token (JWT based on service-account-key.json)
            GA-->>-S: Return Access Token
            Note over S: Store token and expiry (GoogleAuth::refresh_token)
        end

        Note over S: Prepare Gemini API request payload (JSON with prompt)
        S->>+GAPI: Translate Request (POST /v1beta/models/gemini-pro:generateContent with sentence & token)
        GAPI-->>-S: Translation Response (JSON with translated text)
        Note over S: Parse response, extract translated text

        S->>C: Send Translated Sentence
    end

    C->>S: Disconnect
    Note over S: Close session (Session::close)

```

## 2. Measurement Flow (RTT & API Latency)

This diagram focuses specifically on how the client measures Round Trip Time (RTT) and how the server measures the latency of the Gemini API call.

```mermaid
sequenceDiagram
    participant C as TCP Client
    participant S as TCP Server
    participant GC as GeminiClient (in Server)
    participant GAPI as Gemini API

    %% Client RTT Measurement %%
    C->>C: Start RTT Timer (before asio::write in send_and_receive)
    C->>S: Send Message
    S->>GC: Process Message & Initiate API Request
    GC->>GC: Start API Latency Timer (in execute_request)
    GC->>GAPI: Send API Request
    GAPI-->>GC: API Response
    GC->>GC: Stop API Latency Timer (in poll_multi_handle)
    GC->>GC: Calculate & Record API Latency
    GC->>S: Return Translation
    S->>C: Send Response
    C->>C: Stop RTT Timer (after asio::read_until in send_and_receive)
    C->>C: Calculate & Record RTT (rtt_ms)