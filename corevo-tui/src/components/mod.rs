pub mod config;
pub mod history;
pub mod home;
pub mod propose;
pub mod voting;

use ratatui::Frame;

use crate::app::App;

/// Trait for UI components
pub trait Component {
    fn render(&self, app: &App, frame: &mut Frame);
}
