use anyhow::Result;
use ares_core::AresConfig;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

pub enum AgentEvent {
    Token(String),
    ToolCall {
        name: String,
        args: Value,
    },
    RequiresApproval {
        name: String,
        args: Value,
        approval_tx: oneshot::Sender<bool>,
    },
    ToolResult {
        name: String,
        args: Value,
        result: String,
    },
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
    call_type: String,
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
        let api_key = config
            .llm_api_key
            .clone()
            .unwrap_or_else(|| std::env::var("ARES_LLM_API_KEY").unwrap_or_default());
        let mut endpoint = config.llm_base_url.clone().unwrap_or_else(|| {
            std::env::var("ARES_LLM_ENDPOINT")
                .unwrap_or_else(|_| "https://api.openai.com/v1".to_string())
        });

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
            tx.send(AgentEvent::Error(
                "ARES_LLM_API_KEY is not set. Please export it to enable the agent.".to_string(),
            ))
            .await?;
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

    async fn run_loop(
        &self,
        messages: &mut Vec<ChatMessage>,
        tx: mpsc::Sender<AgentEvent>,
    ) -> Result<()> {
        loop {
            let tools = self.get_tools();
            let body = json!({
                "model": self.model,
                "messages": messages,
                "tools": tools,
                "tool_choice": "auto",
                "temperature": 0.0
            });

            let response = self
                .client
                .post(&self.endpoint)
                .header("Authorization", format!("Bearer {}", self.api_key))
                .header("Content-Type", "application/json")
                .json(&body)
                .send()
                .await?;

            if !response.status().is_success() {
                let err_text = response.text().await?;
                tx.send(AgentEvent::Error(format!("LLM API Error: {}", err_text)))
                    .await?;
                break;
            }

            let resp_json: Value = response.json().await?;
            let choice = &resp_json["choices"][0]["message"];

            if let Some(content) = choice["content"].as_str() {
                if !content.is_empty() {
                    let chars: Vec<char> = content.chars().collect();
                    for chunk in chars.chunks(4) {
                        let s: String = chunk.iter().collect();
                        tokio::time::sleep(tokio::time::Duration::from_millis(15)).await;
                        tx.send(AgentEvent::Token(s)).await?;
                    }
                }
            }

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
                            tx.send(AgentEvent::Error(
                                "LLM returned tool call without id".to_string(),
                            ))
                            .await?;
                            continue;
                        }
                    };
                    let func_name = match tc["function"]["name"].as_str() {
                        Some(s) => s.to_string(),
                        None => {
                            tx.send(AgentEvent::Error(format!(
                                "Tool call {} has no function name",
                                id
                            )))
                            .await?;
                            continue;
                        }
                    };
                    let func_args = match tc["function"]["arguments"].as_str() {
                        Some(s) => s,
                        None => {
                            tx.send(AgentEvent::Error(format!(
                                "Tool call {} has no arguments",
                                id
                            )))
                            .await?;
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
                        })
                        .await?;

                        let approved = approval_rx.await.unwrap_or(false);
                        if !approved {
                            let result = "Execution denied by IronCurtain policy.".to_string();
                            tx.send(AgentEvent::ToolResult {
                                name: func_name.clone(),
                                args: args.clone(),
                                result: result.clone(),
                            })
                            .await?;
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

                    tx.send(AgentEvent::ToolCall {
                        name: func_name.clone(),
                        args: args.clone(),
                    })
                    .await?;

                    let result = self.execute_tool(&func_name, &args).await;

                    tx.send(AgentEvent::ToolResult {
                        name: func_name.clone(),
                        args: args.clone(),
                        result: result.clone(),
                    })
                    .await?;

                    messages.push(ChatMessage {
                        role: "tool".to_string(),
                        content: Some(result),
                        name: Some(func_name),
                        tool_calls: None,
                        tool_call_id: Some(id),
                    });
                }
            } else {
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
        Your tools in this session read and list files. Neither 'ares_scan' nor 'ares_fuzz' \
        is implemented here; both return an error saying so. Never state or imply that a \
        scan, a fuzz run, or any other analysis happened unless a tool result in this \
        conversation contains its output, and never call a program clean on the strength \
        of an analysis you did not see. Ground every claim in file contents you have read. \
        Be concise, professional, and act as an expert auditor. \
        IMPORTANT: Before executing any tool or providing an answer, you MUST write down your \
        step-by-step reasoning inside <thinking>...</thinking> XML tags."
            .to_string()
    }

    fn get_tools(&self) -> Value {
        json!([
            {
                "type": "function",
                "function": {
                    "name": "ares_scan",
                    "description": "NOT IMPLEMENTED in this agent: the deterministic ARES V3 local judge and AST mapper are not reachable from here. Calling this scans nothing and returns an error. Use the CLI `ares scan <path>` outside this session, or read the sources with read_file.",
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
                // This called a local `ares_scanner::scan` stub that ignored all
                // three arguments and returned `Ok(())`, so the tool result was
                // always "Scan complete. Check the report in ./ares-output" — for
                // a scan that opened no file, ran no analyzer and wrote no report.
                // The model cannot tell that apart from a real scan, and the
                // system prompt made it the first action of every session, so a
                // program nobody had looked at could be summarised as clean. A
                // tool that lies to the model is worse than one that is absent;
                // `ares_fuzz` below has always said so honestly.
                //
                // It is not wired instead of stubbed because the deterministic
                // pipeline lives in ares-cli/src/commands/scan.rs, which this
                // crate cannot depend on (ares-cli depends on ares-orchestrator).
                // A second copy of the scan path here is exactly the fork that
                // GOLDEN RULE 2 — same input, identical output — cannot survive.
                let target_path = args["target_path"].as_str().unwrap_or(".");
                format!(
                    "Error: ares_scan is not implemented in this agent. NOTHING was \
                     scanned in '{target_path}', no file was read and no report exists. \
                     Do not describe a scan as having run. Either run the CLI \
                     `ares scan {target_path}` outside this session and read its JSON \
                     report with read_file, or audit the sources directly with \
                     list_directory and read_file."
                )
            }
            "ares_fuzz" => {
                let target_path = args["target_path"].as_str().unwrap_or(".");
                let _path = PathBuf::from(target_path);

                "Fuzzing is not yet implemented in the orchestrator. Use the CLI `ares fuzz` command.".to_string()
            }
            "read_file" => {
                let file_path = args["file_path"].as_str().unwrap_or("");
                let path = PathBuf::from(file_path);
                if path.is_dir() {
                    return format!(
                        "Error: '{}' is a directory. Use list_directory to see its contents.",
                        file_path
                    );
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
                                if ft.is_dir() {
                                    "[DIR] "
                                } else {
                                    "[FILE]"
                                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use ares_core::AresConfig;

    /// The tool result is a fact the model is handed and cannot verify. Reporting
    /// success for a scan that never ran is how an auditor ends up calling an
    /// unexamined program clean, so the one thing this must never do is sound
    /// like it worked.
    #[tokio::test]
    async fn ares_scan_says_it_did_not_scan() {
        let agent = AgentOrchestrator::new(&AresConfig::default()).unwrap();
        let result = agent
            .execute_tool("ares_scan", &json!({ "target_path": "./my-program" }))
            .await;

        assert!(
            !result.contains("Scan complete"),
            "must not claim success: {result}"
        );
        assert!(
            result.starts_with("Error:"),
            "the model has to be able to tell this apart from a result: {result}"
        );
        assert!(
            result.contains("./my-program"),
            "name the path that was not scanned: {result}"
        );
    }

    /// The advertised description is the only thing the model sees before
    /// choosing a tool; leaving it promising a deterministic scan would keep the
    /// wasted first call the system prompt used to mandate.
    #[tokio::test]
    async fn ares_scan_is_not_advertised_as_working() {
        let agent = AgentOrchestrator::new(&AresConfig::default()).unwrap();
        let tools = agent.get_tools();
        let scan = tools
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["function"]["name"] == "ares_scan")
            .expect("ares_scan is still offered");
        let description = scan["function"]["description"].as_str().unwrap();
        assert!(
            description.to_lowercase().contains("not implemented"),
            "description must not promise a scan it cannot run: {description}"
        );
        assert!(
            !agent.get_system_prompt().contains("Always use 'ares_scan'"),
            "the prompt must not order the model to lead with a tool that errors"
        );
    }
}
