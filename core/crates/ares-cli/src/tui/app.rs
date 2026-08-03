use crate::agent::{AgentEvent, AgentOrchestrator};
use ares_core::AresConfig;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot};
use tui_textarea::TextArea;

#[derive(Clone)]
pub enum UiMessage {
    User(String),
    Agent(String),
    System(String),
    Thinking(String),
}

pub enum AppState {
    Normal,
    IronCurtainModal,
}

pub struct App<'a> {
    pub config: AresConfig,
    pub textarea: TextArea<'a>,
    pub messages: Vec<UiMessage>,
    pub should_quit: bool,
    pub state: AppState,
    pub telemetry_logs: Vec<String>,
    pub orchestrator: Arc<AgentOrchestrator>,
    pub agent_tx: mpsc::Sender<String>,
    pub agent_rx: mpsc::Receiver<AgentEvent>,
    pub current_response: String,
    pub pending_approval: Option<oneshot::Sender<bool>>,
    pub is_loading: bool,
    pub spinner_tick: usize,
    pub is_in_thinking_block: bool,
    pub current_thinking: String,
    pub scroll_position: Option<usize>,
    pub total_lines: usize,
    pub current_context_title: String,
    pub current_context_content: String,
}

impl<'a> App<'a> {
    pub fn flush_response(&mut self) {
        if self.current_response.is_empty() {
            return;
        }

        let text = self.current_response.clone();
        let mut current_idx = 0;

        while let Some(start) = text[current_idx..].find("<thinking>") {
            let abs_start = current_idx + start;

            let before = text[current_idx..abs_start].trim();
            if !before.is_empty() {
                self.messages.push(UiMessage::Agent(before.to_string()));
            }

            if let Some(end) = text[abs_start..].find("</thinking>") {
                let abs_end = abs_start + end;
                let thinking = text[abs_start + 10..abs_end].trim();
                if !thinking.is_empty() {
                    self.messages
                        .push(UiMessage::Thinking(thinking.to_string()));
                }
                current_idx = abs_end + 11;
            } else {
                let thinking = text[abs_start + 10..].trim();
                if !thinking.is_empty() {
                    self.messages
                        .push(UiMessage::Thinking(thinking.to_string()));
                }
                current_idx = text.len();
                break;
            }
        }

        if current_idx < text.len() {
            let rest = text[current_idx..].trim();
            if !rest.is_empty() {
                self.messages.push(UiMessage::Agent(rest.to_string()));
            }
        }

        self.current_response.clear();
    }

    pub fn new(config: AresConfig) -> anyhow::Result<Self> {
        let mut textarea = TextArea::default();
        textarea.set_block(
            ratatui::widgets::Block::default()
                .borders(ratatui::widgets::Borders::ALL)
                .padding(ratatui::widgets::Padding::new(1, 1, 1, 1))
                .title(" Ask ARES (Press Enter to submit, Esc to exit) "),
        );
        textarea.set_cursor_line_style(ratatui::style::Style::default());

        let orchestrator = Arc::new(AgentOrchestrator::new(&config)?);
        let (req_tx, mut req_rx) = mpsc::channel::<String>(32);
        let (res_tx, res_rx) = mpsc::channel::<AgentEvent>(100);

        let orchestrator_clone = Arc::clone(&orchestrator);
        // Spawn the agent listener
        tokio::spawn(async move {
            while let Some(msg) = req_rx.recv().await {
                let _ = orchestrator_clone.send_message(msg, res_tx.clone()).await;
            }
        });

        Ok(Self {
            config,
            textarea,
            messages: vec![
                UiMessage::System("Welcome to ARES V3 Autonomous Auditor.".to_string()),
                UiMessage::Agent("I am your security agent. How can I help you map or fuzz your Solana program today?".to_string()),
            ],
            should_quit: false,
            state: AppState::Normal,
            telemetry_logs: vec!["[System] TUI Initialized".to_string()],
            orchestrator,
            agent_tx: req_tx,
            agent_rx: res_rx,
            current_response: String::new(),
            pending_approval: None,
            is_loading: false,
            spinner_tick: 0,
            is_in_thinking_block: false,
            current_thinking: String::new(),
            scroll_position: None,
            total_lines: 0,
            current_context_title: "No file selected".to_string(),
            current_context_content: "// The context viewer displays files read by the agent.".to_string(),
        })
    }

    pub fn handle_key(&mut self, key: KeyEvent) -> bool {
        match self.state {
            AppState::Normal => self.handle_normal_key(key),
            AppState::IronCurtainModal => {
                // handle modal keys
                match key.code {
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        if let Some(tx) = self.pending_approval.take() {
                            let _ = tx.send(true);
                        }
                        self.state = AppState::Normal;
                    }
                    KeyCode::Char('d') | KeyCode::Char('D') | KeyCode::Esc => {
                        if let Some(tx) = self.pending_approval.take() {
                            let _ = tx.send(false);
                        }
                        self.state = AppState::Normal;
                    }
                    _ => {}
                }
                false
            }
        }
    }

    fn handle_normal_key(&mut self, key: KeyEvent) -> bool {
        match (key.code, key.modifiers) {
            (KeyCode::Esc, _) => {
                self.should_quit = true;
                true
            }
            (KeyCode::Char('c'), KeyModifiers::CONTROL) => {
                self.should_quit = true;
                true
            }
            (KeyCode::PageUp, _) => {
                let current = self
                    .scroll_position
                    .unwrap_or(self.total_lines.saturating_sub(1));
                self.scroll_position = Some(current.saturating_sub(15));
                false
            }
            (KeyCode::PageDown, _) => {
                let current = self
                    .scroll_position
                    .unwrap_or(self.total_lines.saturating_sub(1));
                let next = current.saturating_add(15);
                if next >= self.total_lines.saturating_sub(1) {
                    self.scroll_position = None; // snap to bottom
                } else {
                    self.scroll_position = Some(next);
                }
                false
            }
            (KeyCode::Up, KeyModifiers::CONTROL) => {
                let current = self
                    .scroll_position
                    .unwrap_or(self.total_lines.saturating_sub(1));
                self.scroll_position = Some(current.saturating_sub(3));
                false
            }
            (KeyCode::Down, KeyModifiers::CONTROL) => {
                let current = self
                    .scroll_position
                    .unwrap_or(self.total_lines.saturating_sub(1));
                let next = current.saturating_add(3);
                if next >= self.total_lines.saturating_sub(1) {
                    self.scroll_position = None; // snap to bottom
                } else {
                    self.scroll_position = Some(next);
                }
                false
            }
            (KeyCode::Enter, KeyModifiers::NONE) => {
                // Submit message
                let input = self.textarea.lines().join("\n");
                if !input.trim().is_empty() {
                    self.messages.push(UiMessage::User(input.clone()));
                    self.is_loading = true;
                    self.scroll_position = None; // snap to bottom on send

                    // Send to agent
                    let _ = self.agent_tx.try_send(input);

                    // Clear textarea
                    self.textarea.delete_line_by_head();
                    self.textarea.delete_line_by_end();
                }
                false
            }
            _ => {
                self.textarea.input(key);
                false
            }
        }
    }

    pub fn tick(&mut self) {
        self.spinner_tick = self.spinner_tick.wrapping_add(1);

        while let Ok(event) = self.agent_rx.try_recv() {
            match event {
                AgentEvent::Token(t) => {
                    self.current_response.push_str(&t);
                }
                AgentEvent::RequiresApproval {
                    name,
                    args,
                    approval_tx,
                } => {
                    self.flush_response();
                    self.telemetry_logs.push(format!(
                        "[IronCurtain] Intercepted: {} args: {}",
                        name, args
                    ));
                    self.state = AppState::IronCurtainModal;
                    self.pending_approval = Some(approval_tx);
                    self.is_loading = false; // Pause loading while waiting for user
                }
                AgentEvent::ToolCall { name, args } => {
                    self.flush_response();
                    self.telemetry_logs
                        .push(format!("[Tool] Running {} with args: {}", name, args));
                    self.is_loading = true;
                }
                AgentEvent::ToolResult { name, args, result } => {
                    self.telemetry_logs.push(format!(
                        "[Tool] {} returned ({} bytes)",
                        name,
                        result.len()
                    ));

                    if name == "read_file" {
                        let path = args["path"].as_str().unwrap_or("Unknown File");
                        self.current_context_title = format!(" {} ", path);
                        self.current_context_content = result;
                    } else if name == "list_directory" {
                        let path = args["path"].as_str().unwrap_or("Directory");
                        self.current_context_title = format!(" {} ", path);
                        self.current_context_content = result;
                    }
                }
                AgentEvent::Error(err) => {
                    self.flush_response();
                    self.messages
                        .push(UiMessage::System(format!("[ERROR] {}", err)));
                    self.is_loading = false;
                }
                AgentEvent::Done => {
                    self.flush_response();
                    self.is_loading = false;
                }
            }
        }
    }
}
