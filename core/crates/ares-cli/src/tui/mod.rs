pub mod app;
pub mod events;
pub mod ui;

use anyhow::Result;
use ares_core::AresConfig;
use crossterm::{
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};
use std::io;

pub async fn run_tui(config: &AresConfig) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = app::App::new(config.clone())?;

    // Start event loop
    let res = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    if let Err(err) = res {
        println!("Error running ARES TUI: {:?}", err);
    }

    Ok(())
}

async fn run_app<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    app: &mut app::App<'_>,
) -> Result<()> {
    loop {
        terminal
            .draw(|f| ui::draw(f, app))
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;

        if let Some(event) = events::next_event().await {
            match event {
                events::Event::Input(key_event) => {
                    if app.handle_key(key_event) {
                        return Ok(()); // Quit
                    }
                }
                events::Event::Tick => {
                    app.tick();
                }
            }
        }
    }
}
