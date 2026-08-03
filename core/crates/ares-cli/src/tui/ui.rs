use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};
use textwrap::wrap;

use super::app::{App, AppState, UiMessage};

fn parse_inline_markdown(
    text: &str,
    base_style: Style,
    is_bold: &mut bool,
    is_code: &mut bool,
) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let mut current_text = String::new();

    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if !*is_code && i + 1 < chars.len() && chars[i] == '*' && chars[i + 1] == '*' {
            if !current_text.is_empty() {
                let style = if *is_bold {
                    base_style.add_modifier(Modifier::BOLD)
                } else {
                    base_style
                };
                spans.push(Span::styled(current_text.clone(), style));
                current_text.clear();
            }
            *is_bold = !*is_bold;
            i += 2;
            continue;
        }

        if !*is_bold && chars[i] == '`' {
            if !current_text.is_empty() {
                let style = if *is_code {
                    base_style.fg(Color::Yellow).bg(Color::Rgb(30, 30, 30))
                } else {
                    base_style
                };
                spans.push(Span::styled(current_text.clone(), style));
                current_text.clear();
            }
            *is_code = !*is_code;
            i += 1;
            continue;
        }

        current_text.push(chars[i]);
        i += 1;
    }

    if !current_text.is_empty() {
        let mut style = base_style;
        if *is_bold {
            style = style.add_modifier(Modifier::BOLD);
        }
        if *is_code {
            style = style.fg(Color::Yellow).bg(Color::Rgb(30, 30, 30));
        }
        spans.push(Span::styled(current_text, style));
    }

    spans
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)].as_ref())
        .split(f.area());

    draw_left_pane(f, app, chunks[0]);
    draw_right_pane(f, app, chunks[1]);

    if matches!(app.state, AppState::IronCurtainModal) {
        draw_modal(f, app);
    }
}

fn draw_left_pane(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(5)].as_ref())
        .split(area);

    // Chat History
    let list_width = chunks[0].width.saturating_sub(4) as usize; // account for borders

    let mut messages: Vec<ListItem> = app
        .messages
        .iter()
        .flat_map(|m| render_ui_message(m, list_width))
        .collect();

    // Render streaming current_response
    if !app.current_response.is_empty() {
        let text = &app.current_response;
        let mut current_idx = 0;

        while let Some(start) = text[current_idx..].find("<thinking>") {
            let abs_start = current_idx + start;

            let before = text[current_idx..abs_start].trim();
            if !before.is_empty() {
                messages.extend(render_ui_message(
                    &UiMessage::Agent(before.to_string()),
                    list_width,
                ));
            }

            if let Some(end) = text[abs_start..].find("</thinking>") {
                let abs_end = abs_start + end;
                let thinking = text[abs_start + 10..abs_end].trim();
                if !thinking.is_empty() {
                    messages.extend(render_ui_message(
                        &UiMessage::Thinking(thinking.to_string()),
                        list_width,
                    ));
                }
                current_idx = abs_end + 11;
            } else {
                let thinking = text[abs_start + 10..].trim();
                if !thinking.is_empty() {
                    messages.extend(render_ui_message(
                        &UiMessage::Thinking(thinking.to_string()),
                        list_width,
                    ));
                }
                current_idx = text.len();
                break;
            }
        }

        if current_idx < text.len() {
            let rest = text[current_idx..].trim();
            if !rest.is_empty() {
                messages.extend(render_ui_message(
                    &UiMessage::Agent(rest.to_string()),
                    list_width,
                ));
            }
        }
    }

    // Loading Indicator in chat
    if app.is_loading {
        let spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner = spinners[app.spinner_tick % spinners.len()];
        let text_content = format!(" {} Thinking... ", spinner);
        let padded_text = format!("{:<w$}", text_content, w = list_width);

        let empty_pad = format!("{:<w$}", "", w = list_width);
        let empty_span = Span::styled(empty_pad, Style::default().bg(Color::Rgb(50, 50, 50)));

        let span = Span::styled(
            padded_text,
            Style::default()
                .bg(Color::Rgb(50, 50, 50))
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        );

        let lines = vec![
            Line::from(vec![empty_span.clone()]).alignment(Alignment::Left),
            Line::from(vec![span]).alignment(Alignment::Left),
            Line::from(vec![empty_span]).alignment(Alignment::Left),
        ];
        messages.push(ListItem::new(lines));
    }

    let messages_block = List::new(messages.clone())
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Conversation (PageUp/PageDown to scroll) "),
        )
        .style(Style::default().fg(Color::White));

    app.total_lines = messages.len();

    let mut list_state = ratatui::widgets::ListState::default();
    if !messages.is_empty() {
        let selected = app.scroll_position.unwrap_or(messages.len() - 1);
        let selected = selected.min(messages.len() - 1);
        list_state.select(Some(selected));
    }
    f.render_stateful_widget(messages_block, chunks[0], &mut list_state);

    // Input Box
    f.render_widget(&app.textarea, chunks[1]);
}

fn render_ui_message(m: &UiMessage, width: usize) -> Vec<ListItem<'static>> {
    let mut lines = Vec::new();

    match m {
        UiMessage::User(text) => {
            let wrapped: Vec<_> = text
                .lines()
                .flat_map(|l| wrap(l, width.saturating_sub(6)))
                .collect();
            let max_len = wrapped.iter().map(|w| w.len()).max().unwrap_or(0);
            let bubble_width = max_len + 2; // " " + text + " "

            let empty_pad = format!("{:<w$}", "", w = bubble_width);
            let empty_span = Span::styled(empty_pad, Style::default().bg(Color::Rgb(30, 144, 255)));

            // Top padding
            lines.push(Line::from(vec![empty_span.clone()]).alignment(Alignment::Right));

            for w in wrapped {
                let text_content = format!(" {} ", w);
                let padded_text = format!("{:<w$}", text_content, w = bubble_width);
                let span = Span::styled(
                    padded_text,
                    Style::default()
                        .bg(Color::Rgb(30, 144, 255))
                        .fg(Color::White)
                        .add_modifier(Modifier::BOLD),
                );
                lines.push(Line::from(vec![span]).alignment(Alignment::Right));
            }

            // Bottom padding
            lines.push(Line::from(vec![empty_span]).alignment(Alignment::Right));
        }
        UiMessage::Agent(text) => {
            let empty_pad = format!("{:<w$}", "", w = width);
            let empty_span = Span::styled(empty_pad, Style::default().bg(Color::Rgb(50, 50, 50)));

            // Top padding
            lines.push(Line::from(vec![empty_span.clone()]).alignment(Alignment::Left));

            let mut in_code_block = false;
            let mut is_bold = false;
            let mut is_code = false;
            for line_str in text.lines() {
                if line_str.trim().starts_with("```") {
                    in_code_block = !in_code_block;
                    let pad = format!(" {:<w$} ", line_str, w = width.saturating_sub(2));
                    lines.push(
                        Line::from(vec![Span::styled(
                            pad,
                            Style::default().bg(Color::Rgb(40, 40, 40)).fg(Color::Cyan),
                        )])
                        .alignment(Alignment::Left),
                    );
                    continue;
                }

                let wrapped = wrap(line_str, width.saturating_sub(2));
                let is_header = line_str.starts_with("# ")
                    || line_str.starts_with("## ")
                    || line_str.starts_with("### ");
                for w in wrapped {
                    let w_str = w.into_owned();

                    if in_code_block {
                        let visual_width = w_str.chars().count();
                        let padding_len = width.saturating_sub(2).saturating_sub(visual_width);
                        let trailing_pad = format!("{} ", " ".repeat(padding_len));

                        let mut spans = vec![Span::styled(
                            " ",
                            Style::default().bg(Color::Rgb(30, 30, 30)),
                        )];
                        spans.push(Span::styled(
                            w_str,
                            Style::default()
                                .bg(Color::Rgb(30, 30, 30))
                                .fg(Color::LightGreen),
                        ));
                        spans.push(Span::styled(
                            trailing_pad,
                            Style::default().bg(Color::Rgb(30, 30, 30)),
                        ));
                        lines.push(Line::from(spans).alignment(Alignment::Left));
                    } else {
                        let mut line_base_style =
                            Style::default().bg(Color::Rgb(50, 50, 50)).fg(Color::White);
                        if is_header {
                            line_base_style = line_base_style
                                .fg(Color::LightBlue)
                                .add_modifier(Modifier::BOLD);
                        }

                        let mut spans = parse_inline_markdown(
                            &w_str,
                            line_base_style,
                            &mut is_bold,
                            &mut is_code,
                        );

                        let visual_width: usize =
                            spans.iter().map(|s| s.content.chars().count()).sum();
                        let padding_len = width.saturating_sub(2).saturating_sub(visual_width);
                        let trailing_pad = format!("{} ", " ".repeat(padding_len));

                        spans.insert(
                            0,
                            Span::styled(" ", Style::default().bg(Color::Rgb(50, 50, 50))),
                        );
                        spans.push(Span::styled(
                            trailing_pad,
                            Style::default().bg(Color::Rgb(50, 50, 50)),
                        ));
                        lines.push(Line::from(spans).alignment(Alignment::Left));
                    }
                }
            }

            // Bottom padding
            lines.push(Line::from(vec![empty_span]).alignment(Alignment::Left));
        }
        UiMessage::Thinking(text) => {
            let empty_pad = format!("{:<w$}", "", w = width);
            let empty_span = Span::styled(empty_pad, Style::default().bg(Color::Rgb(40, 40, 40)));

            // Top padding
            lines.push(Line::from(vec![empty_span.clone()]).alignment(Alignment::Left));

            for line_str in text.lines() {
                let wrapped = wrap(line_str, width.saturating_sub(4));
                for w in wrapped {
                    let text_content = format!("  {} ", w);
                    let padded_text = format!("{:<w$}", text_content, w = width);
                    let span = Span::styled(
                        padded_text,
                        Style::default()
                            .bg(Color::Rgb(40, 40, 40))
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    );
                    lines.push(Line::from(vec![span]).alignment(Alignment::Left));
                }
            }

            // Bottom padding
            lines.push(Line::from(vec![empty_span]).alignment(Alignment::Left));
        }
        UiMessage::System(text) => {
            for line_str in text.lines() {
                let wrapped = wrap(line_str, width.saturating_sub(11));
                for w in wrapped {
                    let padded_text = format!(" [System] {} ", w);
                    let span = Span::styled(
                        padded_text,
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::ITALIC),
                    );
                    lines.push(Line::from(vec![span]).alignment(Alignment::Center));
                }
            }
        }
    }

    // Add vertical space between bubbles
    lines.push(Line::from(""));

    lines.into_iter().map(ListItem::new).collect()
}

fn draw_right_pane(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage(50), // Code View
                Constraint::Percentage(40), // Telemetry
                Constraint::Percentage(10), // Status
            ]
            .as_ref(),
        )
        .split(area);

    // 1. Code/Context View
    let title = format!(" Context Viewer: {} ", app.current_context_title);
    let code_block = Paragraph::new(app.current_context_content.as_str())
        .block(Block::default().borders(Borders::ALL).title(title))
        .style(Style::default().fg(Color::LightCyan))
        .wrap(Wrap { trim: false });
    f.render_widget(code_block, chunks[0]);

    // 2. Telemetry / Tool Activity
    let logs: Vec<ListItem> = app
        .telemetry_logs
        .iter()
        .map(|m| ListItem::new(m.as_str()))
        .collect();

    let telemetry_block = List::new(logs).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Agent Telemetry "),
    );
    f.render_widget(telemetry_block, chunks[1]);

    // 3. Status Bar
    let key = &app.orchestrator.api_key;
    let masked_key = if key.is_empty() {
        "UNSET".to_string()
    } else {
        "****".to_string()
    };

    let model = if app.orchestrator.model.is_empty() {
        "default"
    } else {
        &app.orchestrator.model
    };
    let endpoint = &app.orchestrator.endpoint;
    let short_endpoint = endpoint
        .strip_prefix("https://")
        .unwrap_or(endpoint)
        .strip_prefix("http://")
        .unwrap_or(endpoint);

    let status_str = if app.is_loading {
        let spinners = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let spinner = spinners[app.spinner_tick % spinners.len()];
        format!(" Mode: Interactive | LLM: {} | URL: {} | Key: {} | Policy: IronCurtain | {} Working... ", model, short_endpoint, masked_key, spinner)
    } else {
        format!(
            " Mode: Interactive | LLM: {} | URL: {} | Key: {} | Policy: IronCurtain | Idle ",
            model, short_endpoint, masked_key
        )
    };

    let status_block = Paragraph::new(status_str)
        .style(
            Style::default()
                .bg(Color::Blue)
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
        .wrap(Wrap { trim: true });

    f.render_widget(status_block, chunks[2]);
}

fn draw_modal(f: &mut Frame, _app: &mut App) {
    let block = Paragraph::new(
        "IronCurtain Triggered\nAgent wants to modify files.\n\n[A]llow  [D]eny  [E]dit",
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" SECURITY ALERT ")
            .style(Style::default().fg(Color::Red)),
    )
    .alignment(ratatui::layout::Alignment::Center)
    .wrap(Wrap { trim: true });

    let area = centered_rect(50, 20, f.area());
    f.render_widget(Clear, area); // Clear background
    f.render_widget(block, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
