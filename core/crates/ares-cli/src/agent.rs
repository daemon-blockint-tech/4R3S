use anyhow::Result;
use ares_core::AresConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

pub enum AgentEvent {
    Token(String),
    ToolCall { name: String, args: Value },
    RequiresApproval { name: String, args: Value, approval_tx: oneshot::Sender<bool> },
    ToolResult { name: String, args: Value, result: String },
    Error(String),
    Done,
}

#[derive(Serialize)]
struct ChatMessage {
    role: String,
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_calls: Option<Vec<ToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_call_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ToolCall {
    id: String,
    #[serde(rename = "type")]
    call_type: String, // "function"
    function: FunctionCall,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FunctionCall {
    name: String,
    arguments: String,
}

pub struct AgentOrchestrator {
    pub client: Client,
    pub api_key: String,
    pub endpoint: String,
    pub model: String,
    pub config: AresConfig,
}

impl AgentOrchestrator {
    pub fn new(config: &AresConfig) -> Result<Self> {
        let api_key = config.llm_api_key.clone().unwrap_or_else(|| std::env::var("ARES_LLM_API_KEY").unwrap_or_default());
        let mut endpoint = config.llm_base_url.clone().unwrap_or_else(|| {
            std::env::var("ARES_LLM_ENDPOINT").unwrap_or_else(|_| "https://api.openai.com/v1".to_string())
        });

        // Normalize endpoint if needed
        let trimmed = endpoint.trim_end_matches('/');
        if !trimmed.ends_with("/chat/completions") && !trimmed.ends_with("/messages") {
            endpoint = format!("{}/chat/completions", trimmed);
        } else {
            endpoint = trimmed.to_string();
        }

        let model = config.llm_model.clone();

        Ok(Self {
            client: Client::new(),
            api_key,
            endpoint,
            model,
            config: config.clone(),
        })
    }

    pub async fn send_message(&self, message: String, tx: mpsc::Sender<AgentEvent>) -> Result<()> {
        if self.api_key.is_empty() {
            tx.send(AgentEvent::Error("ARES_LLM_API_KEY is not set. Please export it to enable the agent.".to_string())).await?;
            tx.send(AgentEvent::Done).await?;
            return Ok(());
        }

        let mut messages = vec![
            ChatMessage {
                role: "system".to_string(),
                content: Some(self.get_system_prompt()),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
            ChatMessage {
                role: "user".to_string(),
                content: Some(message),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            },
        ];

        self.run_loop(&mut messages, tx).await
    }

    async fn run_loop(&self, messages: &mut Vec<ChatMessage>, tx: mpsc::Sender<AgentEvent>) -> Result<()> {
        loop {
            let tools = self.get_tools();
            let body = json!({
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": 0.0
            });

            let response = self.client.post(&self.endpoint)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await?;

            if !response.status().is_success() {
                let err_text = response.text().await?;
                tx.send(AgentEvent::Error(format!("LLM API Error: {}", err_text))).await?;
                break;
            }

            let resp_json: Value = response.json().await?;
            let choice = &resp_json["choices"][0]["message"];

            // Extract content if any
            if let Some(content) = choice["content"].as_str() {
                if !content.is_empty() {
                    // We don't support true streaming in this basic loop yet, so just send chunks
                    let chars: Vec<char> = content.chars().collect();
                    for chunk in chars.chunks(4) {
                        let s: String = chunk.iter().collect();
                        tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
                        tx.send(AgentEvent::Token(s)).await?;
                    }
                }
            }

            // Handle tool calls
            if let Some(tool_calls) = choice["tool_calls"].as_array() {
                let assistant_message = ChatMessage {
                    role: "assistant".to_string(),
                    content: choice["content"].as_str().map(|s| s.to_string()),
                    name: None,
                    tool_calls: Some(serde_json::from_value(choice["tool_calls"].clone())?),
                    tool_call_id: None,
                };
                messages.push(assistant_message);

                for tc in tool_calls {
                    let id = match tc["id"].as_str() {
                        Some(s) => s.to_string(),
                        None => {
                            tx.send(AgentEvent::Error("LLM returned tool call without id".to_string())).await?;
                            continue;
                        }
                    };
                    let func_name = match tc["function"]["name"].as_str() {
                        Some(s) => s.to_string(),
                        None => {
                            tx.send(AgentEvent::Error(format!("Tool call {} has no function name", id))).await?;
                            continue;
                        }
                    };
                    let func_args = match tc["function"]["arguments"].as_str() {
                        Some(s) => s,
                        None => {
                            tx.send(AgentEvent::Error(format!("Tool call {} has no arguments", id))).await?;
                            continue;
                        }
                    };
                    let args: Value = serde_json::from_str(func_args).unwrap_or(json!({}));

                    let is_mutating = func_name == "ares_fuzz";

                    if is_mutating {
                        let (approval_tx, approval_rx) = oneshot::channel();
                        tx.send(AgentEvent::RequiresApproval {
                            name: func_name.clone(),
                            args: args.clone(),
                            approval_tx,
                        }).await?;

                        // Wait for UI response
                        let approved = approval_rx.await.unwrap_or(false);
                        if !approved {
                            let result = "Execution denied by IronCurtain policy.".to_string();
                            tx.send(AgentEvent::ToolResult { name: func_name.clone(), args: args.clone(), result: result.clone() }).await?;
                            messages.push(ChatMessage {
                                role: "tool".to_string(),
                                content: Some(result),
                                name: Some(func_name),
                                tool_calls: None,
                                tool_call_id: Some(id),
                            });
                            continue;
                        }
                    }

                    tx.send(AgentEvent::ToolCall { name: func_name.clone(), args: args.clone() }).await?;
                    
                    // Execute tool
                    let result = self.execute_tool(&func_name, &args).await;
                    
                    tx.send(AgentEvent::ToolResult { name: func_name.clone(), args: args.clone(), result: result.clone() }).await?;

                    messages.push(ChatMessage {
                        role: "tool".to_string(),
                        content: Some(result),
                        name: Some(func_name),
                        tool_calls: None,
                        tool_call_id: Some(id),
                    });
                }
            } else {
                // No tool calls, we are done
                messages.push(ChatMessage {
                    role: "assistant".to_string(),
                    content: choice["content"].as_str().map(|s| s.to_string()),
                    name: None,
                    tool_calls: None,
                    tool_call_id: None,
                });
                break;
            }
        }

        tx.send(AgentEvent::Done).await?;
        Ok(())
    }

    fn get_system_prompt(&self) -> String {
        "You are ARES V3, an autonomous AI security auditor for Solana smart contracts. \
        You have access to tools to scan, map, and fuzz code. \
        Always use 'ares_scan' to run a static deterministic analysis on a workspace first. \
        Be concise, professional, and act as an expert auditor. \
        IMPORTANT: Before executing any tool or providing an answer, you MUST write down your \
        step-by-step reasoning inside <thinking>...</thinking> XML tags.".to_string()
    }

    fn get_tools(&self) -> Value {
        json!([
            {
                "type": "function",
                "function": {
                    "name": "ares_scan",
                    "description": "Run the deterministic ARES V3 local judge and AST mapper on a target directory.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_path": {
                                "type": "string",
                                "description": "The path to the Solana program to scan."
                            }
                        },
                        "required": ["target_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "ares_fuzz",
                    "description": "Run the Trident fuzzer on the target directory.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "target_path": {
                                "type": "string"
                            }
                        },
                        "required": ["target_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "read_file",
                    "description": "Read the contents of a specific file.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "file_path": {
                                "type": "string"
                            }
                        },
                        "required": ["file_path"]
                    }
                }
            },
            {
                "type": "function",
                "function": {
                    "name": "list_directory",
                    "description": "List all files and subdirectories in a specific directory.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "dir_path": {
                                "type": "string",
                                "description": "The path to the directory to list."
                            }
                        },
                        "required": ["dir_path"]
                    }
                }
            }
        ])
    }

    async fn execute_tool(&self, name: &str, args: &Value) -> String {
        match name {
            "ares_scan" => {
                let target_path = args["target_path"].as_str().unwrap_or(".");
                let path = PathBuf::from(target_path);
                
                // Wrap the call to scan execute. In reality we should intercept the logs, 
                // but for now we'll run it and return success assuming it creates the report.
                let output_dir = PathBuf::from("./ares-output");
                let res = crate::commands::scan::execute(
                    &path,
                    &self.config,
                    None,
                    true,
                    false, // Fuzz disabled by default for scan tool
                    false, // PoC disabled
                    false, // AST scan: unmeasured against a real corpus, opt-in only
                    3600,
                    &output_dir
                ).await;

                match res {
                    Ok(_) => format!("Scan complete. Check the report in {:?}", output_dir),
                    Err(e) => format!("Scan failed: {}", e),
                }
            }
            "ares_fuzz" => {
                let target_path = args["target_path"].as_str().unwrap_or(".");
                let path = PathBuf::from(target_path);
                
                let res = crate::commands::fuzz::execute(&path, 1000, None, false).await;
                match res {
                    Ok(_) => "Fuzzing complete.".to_string(),
                    Err(e) => format!("Fuzzing failed: {}", e),
                }
            }
            "read_file" => {
                let file_path = args["file_path"].as_str().unwrap_or("");
                let path = PathBuf::from(file_path);
                if path.is_dir() {
                    return format!("Error: '{}' is a directory. Use list_directory to see its contents.", file_path);
                }
                match tokio::fs::read_to_string(file_path).await {
                    Ok(content) => content,
                    Err(e) => format!("Failed to read file: {}", e),
                }
            }
            "list_directory" => {
                let dir_path = args["dir_path"].as_str().unwrap_or(".");
                let path = PathBuf::from(dir_path);
                if !path.exists() {
                    return format!("Error: Directory '{}' does not exist.", dir_path);
                }
                if !path.is_dir() {
                    return format!("Error: '{}' is not a directory.", dir_path);
                }
                match tokio::fs::read_dir(path).await {
                    Ok(mut entries) => {
                        let mut files = Vec::new();
                        while let Ok(Some(entry)) = entries.next_entry().await {
                            let file_type = if let Ok(ft) = entry.file_type().await {
                                if ft.is_dir() { "[DIR] " } else { "[FILE]" }
                            } else {
                                "[UKWN]"
                            };
                            let file_name = entry.file_name().to_string_lossy().to_string();
                            files.push(format!("{} {}", file_type, file_name));
                        }
                        if files.is_empty() {
                            format!("Directory '{}' is empty.", dir_path)
                        } else {
                            format!("Contents of '{}':\n{}", dir_path, files.join("\n"))
                        }
                    }
                    Err(e) => format!("Failed to list directory: {}", e),
                }
            }
            _ => format!("Unknown tool: {}", name),
        }
    }
}
