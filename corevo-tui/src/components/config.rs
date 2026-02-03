use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph},
    Frame,
};

use crate::app::App;

pub struct ConfigComponent;

impl ConfigComponent {
    pub fn render(app: &App, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Min(16),    // Form fields
                Constraint::Length(3),  // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Configuration")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // Form fields
        let form_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Chain URL
                Constraint::Length(3),  // MongoDB URI
                Constraint::Length(3),  // MongoDB DB
                Constraint::Length(3),  // Secret URI
                Constraint::Min(1),     // Spacer
            ])
            .split(chunks[1]);

        // Helper to render a field
        let render_field = |frame: &mut Frame, area: ratatui::layout::Rect, label: &str, value: &str, focused: bool, is_secret: bool| {
            let display_value = if is_secret && !value.is_empty() {
                "*".repeat(value.len().min(20))
            } else {
                value.to_string()
            };

            let style = if focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };

            let border_style = if focused {
                Style::default().fg(Color::Yellow)
            } else {
                Style::default()
            };

            let field = Paragraph::new(Line::from(vec![
                Span::styled(format!("{}: ", label), Style::default().fg(Color::Cyan)),
                Span::styled(display_value, style),
                if focused {
                    Span::styled("_", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK))
                } else {
                    Span::raw("")
                },
            ]))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style),
            );
            frame.render_widget(field, area);
        };

        render_field(
            frame,
            form_chunks[0],
            "Chain URL",
            &app.config_form.chain_url,
            app.config_form.focused_field == 0,
            false,
        );

        render_field(
            frame,
            form_chunks[1],
            "MongoDB URI",
            &app.config_form.mongodb_uri,
            app.config_form.focused_field == 1,
            false,
        );

        render_field(
            frame,
            form_chunks[2],
            "MongoDB DB",
            &app.config_form.mongodb_db,
            app.config_form.focused_field == 2,
            false,
        );

        render_field(
            frame,
            form_chunks[3],
            "Secret URI (not saved)",
            &app.secret_uri,
            app.config_form.focused_field == 3,
            true,
        );

        // Help
        let help = Paragraph::new("Tab/Up/Down: Navigate | Ctrl+V: Paste | Ctrl+U: Clear | Ctrl+S: Save | Esc: Back")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[2]);
    }
}
