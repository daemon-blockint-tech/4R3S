use crossterm::event::{self, Event as CrosstermEvent, KeyEvent};
use std::time::Duration;

pub enum Event {
    Input(KeyEvent),
    Tick,
}

pub async fn next_event() -> Option<Event> {
    // We poll for events to allow non-blocking UI
    if event::poll(Duration::from_millis(50)).unwrap_or(false) {
        if let Ok(CrosstermEvent::Key(key)) = event::read() {
            return Some(Event::Input(key));
        }
    }
    Some(Event::Tick)
}
