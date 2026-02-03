use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::App;

pub struct VotingComponent;

impl VotingComponent {
    pub fn render(app: &App, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Length(6),  // Context info
                Constraint::Min(10),    // Vote options
                Constraint::Length(3),  // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Voting Session")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // Context info
        let context_text = if let Some(ref ctx) = app.selected_context {
            vec![
                Line::from(vec![
                    Span::styled("Context: ", Style::default().fg(Color::Yellow)),
                    Span::raw(format!("{}", ctx)),
                ]),
                Line::from(""),
                Line::from(if app.secret_uri.is_empty() {
                    Span::styled(
                        "Warning: No account configured. Go to Config to set up.",
                        Style::default().fg(Color::Red),
                    )
                } else {
                    Span::styled("Account configured", Style::default().fg(Color::Green))
                }),
            ]
        } else {
            vec![Line::from(Span::styled(
                "No voting context selected. Go to History to select one.",
                Style::default().fg(Color::DarkGray),
            ))]
        };

        let context_info = Paragraph::new(context_text)
            .block(Block::default().title("Current Session").borders(Borders::ALL));
        frame.render_widget(context_info, chunks[1]);

        // Vote options (only if context is selected and account configured)
        if app.selected_context.is_some() && !app.secret_uri.is_empty() {
            let vote_options = vec![
                ("1", "Aye", "Vote in favor", Color::Green),
                ("2", "Nay", "Vote against", Color::Red),
                ("3", "Abstain", "Abstain from voting", Color::Blue),
            ];

            let items: Vec<ListItem> = vote_options
                .iter()
                .enumerate()
                .map(|(i, (key, label, desc, color))| {
                    let style = if i == app.selected_index {
                        Style::default().fg(*color).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    ListItem::new(Line::from(vec![
                        Span::styled(format!("[{}] ", key), Style::default().fg(Color::Cyan)),
                        Span::styled(*label, style),
                        Span::styled(format!(" - {}", desc), Style::default().fg(Color::DarkGray)),
                    ]))
                })
                .collect();

            let menu = List::new(items)
                .block(Block::default().title("Cast Your Vote").borders(Borders::ALL))
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            frame.render_widget(menu, chunks[2]);
        } else {
            let placeholder = Paragraph::new(
                "Select a voting context from History and configure your account in Config",
            )
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().title("Cast Your Vote").borders(Borders::ALL));
            frame.render_widget(placeholder, chunks[2]);
        }

        // Help
        let help = Paragraph::new("1/2/3: Vote | Enter: Confirm | Esc: Back to Home")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[3]);
    }
}
