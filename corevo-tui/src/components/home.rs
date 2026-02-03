use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};

use crate::app::{App, LoadingState};

pub struct HomeComponent;

impl HomeComponent {
    pub fn render(app: &App, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(2)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Length(9),  // Info box (chain, db, blank, account, balance)
                Constraint::Min(10),    // Menu
                Constraint::Length(3),  // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("CoReVo - Commit-Reveal Voting")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // Info box
        let mut info_text = vec![
            Line::from(vec![
                Span::styled("Chain: ", Style::default().fg(Color::Yellow)),
                Span::raw(&app.config_form.chain_url),
            ]),
            Line::from(vec![
                Span::styled("Database: ", Style::default().fg(Color::Yellow)),
                Span::raw(&app.config_form.mongodb_db),
            ]),
            Line::from(""),
        ];

        // Show account status and address
        if let Some(ref address) = app.derived_address {
            info_text.push(Line::from(vec![
                Span::styled("Account: ", Style::default().fg(Color::Yellow)),
                Span::styled(address.clone(), Style::default().fg(Color::Green)),
            ]));

            // Show balance
            let balance_span = match &app.balance_loading {
                LoadingState::Idle => Span::styled("--", Style::default().fg(Color::DarkGray)),
                LoadingState::Loading => Span::styled("Loading...", Style::default().fg(Color::Yellow)),
                LoadingState::Loaded => {
                    if let Some(ref formatted) = app.formatted_balance() {
                        Span::styled(formatted.clone(), Style::default().fg(Color::Green))
                    } else {
                        Span::styled("0", Style::default().fg(Color::DarkGray))
                    }
                }
                LoadingState::Error(e) => Span::styled(
                    format!("Error: {}", if e.len() > 30 { &e[..30] } else { e }),
                    Style::default().fg(Color::Red)
                ),
            };
            info_text.push(Line::from(vec![
                Span::styled("Balance: ", Style::default().fg(Color::Yellow)),
                balance_span,
            ]));
        } else if app.secret_uri.is_empty() {
            info_text.push(Line::from(vec![
                Span::styled("Account: ", Style::default().fg(Color::Yellow)),
                Span::styled("Not configured (go to Config)", Style::default().fg(Color::Red)),
            ]));
        } else {
            info_text.push(Line::from(vec![
                Span::styled("Account: ", Style::default().fg(Color::Yellow)),
                Span::styled("Invalid secret URI", Style::default().fg(Color::Red)),
            ]));
        }

        let info = Paragraph::new(info_text)
            .block(Block::default().title("Status").borders(Borders::ALL));
        frame.render_widget(info, chunks[1]);

        // Menu
        let menu_items = vec![
            ("1", "History", "View past voting contexts and results"),
            ("2", "Voting", "Participate in active voting sessions"),
            ("3", "Propose", "Create a new voting context"),
            ("4", "Config", "Edit settings and enter secret URI"),
            ("q", "Quit", "Exit the application"),
        ];

        let items: Vec<ListItem> = menu_items
            .iter()
            .enumerate()
            .map(|(i, (key, label, desc))| {
                let style = if i == app.selected_index {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
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
            .block(Block::default().title("Menu").borders(Borders::ALL))
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_widget(menu, chunks[2]);

        // Help
        let help = Paragraph::new("Press number keys to navigate, or use arrow keys and Enter")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[3]);

        // Error message overlay if present
        if let Some(ref error) = app.error_message {
            render_error_popup(frame, error);
        }
    }
}

fn render_error_popup(frame: &mut Frame, message: &str) {
    let area = centered_rect(60, 20, frame.area());
    let popup = Paragraph::new(message)
        .style(Style::default().fg(Color::Red))
        .block(
            Block::default()
                .title("Error")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Red)),
        );
    frame.render_widget(ratatui::widgets::Clear, area);
    frame.render_widget(popup, area);
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
