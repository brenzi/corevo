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
        let account_on_chain = app.is_account_on_chain();
        if let Some(ref address) = app.derived_address {
            // Show "Copied!" indicator if recently copied
            let account_suffix = if app.should_show_copied() {
                vec![
                    Span::styled(" (", Style::default().fg(Color::DarkGray)),
                    Span::styled("Copied!", Style::default().fg(Color::Green)),
                    Span::styled(")", Style::default().fg(Color::DarkGray)),
                ]
            } else {
                vec![
                    Span::styled(" (click to copy)", Style::default().fg(Color::DarkGray)),
                ]
            };

            let mut account_line = vec![
                Span::styled("Account: ", Style::default().fg(Color::Yellow)),
                Span::styled(address.clone(), Style::default().fg(Color::Green).add_modifier(Modifier::UNDERLINED)),
            ];
            account_line.extend(account_suffix);
            info_text.push(Line::from(account_line));

            // Show balance
            let balance_line = match &app.balance_loading {
                LoadingState::Idle => vec![
                    Span::styled("Balance: ", Style::default().fg(Color::Yellow)),
                    Span::styled("--", Style::default().fg(Color::DarkGray)),
                ],
                LoadingState::Loading => vec![
                    Span::styled("Balance: ", Style::default().fg(Color::Yellow)),
                    Span::styled("Loading...", Style::default().fg(Color::Yellow)),
                ],
                LoadingState::Loaded => {
                    let bal = app.balance.unwrap_or(0);
                    if bal > 0 {
                        vec![
                            Span::styled("Balance: ", Style::default().fg(Color::Yellow)),
                            Span::styled(app.formatted_balance().unwrap_or_default(), Style::default().fg(Color::Green)),
                        ]
                    } else {
                        vec![
                            Span::styled("Balance: ", Style::default().fg(Color::Yellow)),
                            Span::styled("0 ", Style::default().fg(Color::Red)),
                            Span::styled("(fund account to vote/propose)", Style::default().fg(Color::DarkGray)),
                        ]
                    }
                }
                LoadingState::Error(e) => {
                    let short_err = if e.len() > 25 { &e[..25] } else { e };
                    vec![
                        Span::styled("Balance: ", Style::default().fg(Color::Yellow)),
                        Span::styled(format!("Error: {} ", short_err), Style::default().fg(Color::Red)),
                        Span::styled("(fund account first)", Style::default().fg(Color::DarkGray)),
                    ]
                }
            };
            info_text.push(Line::from(balance_line));
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

        // Menu - check if account can perform on-chain actions
        let can_use_chain = account_on_chain == Some(true);
        let can_announce = can_use_chain && app.has_announced_pubkey() == Some(false);

        // Build menu with dynamic descriptions based on state
        let vote_desc = if !can_use_chain && app.derived_address.is_some() {
            "Fund account first"
        } else {
            "Participate in active voting sessions"
        };
        let propose_desc = if !can_use_chain && app.derived_address.is_some() {
            "Fund account first"
        } else {
            "Create a new voting context"
        };
        let announce_desc = if !can_use_chain && app.derived_address.is_some() {
            "Fund account first"
        } else {
            match app.has_announced_pubkey() {
                Some(true) => "Already announced",
                Some(false) => "Announce your X25519 public key",
                None => "Load history first to check status",
            }
        };

        let menu_items = vec![
            ("1", "History", "View past voting contexts and results", false),
            ("2", "Vote", vote_desc, !can_use_chain && app.derived_address.is_some()),
            ("3", "Propose", propose_desc, !can_use_chain && app.derived_address.is_some()),
            ("4", "Config", "Edit settings and enter secret URI", false),
            ("5", "Announce Pubkey", announce_desc, !can_announce),
            ("q", "Quit", "Exit the application", false),
        ];

        let items: Vec<ListItem> = menu_items
            .iter()
            .enumerate()
            .map(|(i, (key, label, desc, is_disabled))| {
                let style = if i == app.selected_index {
                    if *is_disabled {
                        Style::default().fg(Color::DarkGray).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                    }
                } else if *is_disabled {
                    Style::default().fg(Color::DarkGray)
                } else {
                    Style::default()
                };
                ListItem::new(Line::from(vec![
                    Span::styled(format!("[{}] ", key), Style::default().fg(if *is_disabled { Color::DarkGray } else { Color::Cyan })),
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

        // Announce loading overlay
        match &app.announce_loading {
            LoadingState::Loading => {
                render_status_popup(frame, "Announcing public key...", Color::Yellow);
            }
            LoadingState::Loaded => {
                render_status_popup(frame, "Public key announced successfully!", Color::Green);
            }
            LoadingState::Error(e) => {
                render_error_popup(frame, &format!("Announce failed: {}", e));
            }
            LoadingState::Idle => {}
        }

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

fn render_status_popup(frame: &mut Frame, message: &str, color: Color) {
    let area = centered_rect(50, 15, frame.area());
    let popup = Paragraph::new(message)
        .style(Style::default().fg(color))
        .block(
            Block::default()
                .title("Status")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(color)),
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
