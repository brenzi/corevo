use corevo_lib::{VoteStatus, format_account_ss58, ss58_prefix_for_chain};
use ratatui::{
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
    Frame,
};

use crate::app::{App, LoadingState};

pub struct HistoryComponent;

impl HistoryComponent {
    pub fn render(app: &App, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3),  // Title
                Constraint::Length(6),  // My Account pane
                Constraint::Min(10),    // Content
                Constraint::Length(3),  // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Voting History")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // My Account pane
        Self::render_account_pane(app, frame, chunks[1]);

        // Content based on loading state
        match &app.history_loading {
            LoadingState::Idle => {
                let msg = Paragraph::new("Press Enter to load history")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(msg, chunks[2]);
            }
            LoadingState::Loading => {
                let msg = Paragraph::new("Loading history from indexer...")
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(msg, chunks[2]);
            }
            LoadingState::Error(e) => {
                let msg = Paragraph::new(format!("Error: {}", e))
                    .style(Style::default().fg(Color::Red))
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(msg, chunks[2]);
            }
            LoadingState::Loaded => {
                if let Some(ref history) = app.history {
                    // Split content into list and details
                    let content_chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                        .split(chunks[2]);

                    // Context list with stateful rendering for scroll support
                    let contexts: Vec<&corevo_lib::CorevoContext> =
                        history.contexts.keys().collect();
                    let items: Vec<ListItem> = contexts
                        .iter()
                        .map(|ctx| {
                            ListItem::new(format!("{}", ctx))
                        })
                        .collect();

                    let list = List::new(items)
                        .block(Block::default().title(format!("Contexts ({})", contexts.len())).borders(Borders::ALL))
                        .highlight_style(
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
                        )
                        .highlight_symbol("> ");

                    // Create list state with current selection
                    let mut list_state = ListState::default();
                    list_state.select(Some(app.selected_index));
                    frame.render_stateful_widget(list, content_chunks[0], &mut list_state);

                    // Details for selected context
                    if let Some(ctx) = contexts.get(app.selected_index) {
                        if let Some(summary) = history.contexts.get(*ctx) {
                            // Get SS58 prefix for formatting addresses
                            let ss58_prefix = ss58_prefix_for_chain(&app.config_form.chain_url);

                            let proposer_ss58 = format_account_ss58(&summary.proposer, ss58_prefix);

                            // Count votes by type
                            let mut aye_count = 0;
                            let mut nay_count = 0;
                            let mut abstain_count = 0;
                            let mut committed_count = 0;
                            let mut unknown_count = 0;
                            let mut uncast_count = 0;

                            for voter in &summary.voters {
                                match summary.votes.get(voter) {
                                    None => uncast_count += 1,
                                    Some(VoteStatus::Committed(_)) => committed_count += 1,
                                    Some(VoteStatus::Revealed(Ok(vote))) => match vote {
                                        corevo_lib::CorevoVote::Aye => aye_count += 1,
                                        corevo_lib::CorevoVote::Nay => nay_count += 1,
                                        corevo_lib::CorevoVote::Abstain => abstain_count += 1,
                                    },
                                    Some(VoteStatus::Revealed(Err(_))) => unknown_count += 1,
                                    Some(VoteStatus::RevealedWithoutCommitment) => unknown_count += 1,
                                }
                            }

                            let mut lines = vec![
                                Line::from(vec![
                                    Span::styled("Proposer: ", Style::default().fg(Color::Yellow)),
                                    Span::raw(proposer_ss58),
                                ]),
                                Line::from(vec![
                                    Span::styled("Voters: ", Style::default().fg(Color::Yellow)),
                                    Span::raw(format!("{}", summary.voters.len())),
                                ]),
                                Line::from(vec![
                                    Span::styled("  Aye: ", Style::default().fg(Color::Green)),
                                    Span::raw(format!("{}", aye_count)),
                                    Span::styled("  Nay: ", Style::default().fg(Color::Red)),
                                    Span::raw(format!("{}", nay_count)),
                                    Span::styled("  Abstain: ", Style::default().fg(Color::Blue)),
                                    Span::raw(format!("{}", abstain_count)),
                                ]),
                                Line::from(vec![
                                    Span::styled("  Unrevealed: ", Style::default().fg(Color::Yellow)),
                                    Span::raw(format!("{}", committed_count)),
                                    Span::styled("  Uncast: ", Style::default().fg(Color::DarkGray)),
                                    Span::raw(format!("{}", uncast_count)),
                                    if unknown_count > 0 {
                                        Span::styled(format!("  Unknown: {}", unknown_count), Style::default().fg(Color::DarkGray))
                                    } else {
                                        Span::raw("")
                                    },
                                ]),
                                Line::from(""),
                                Line::from(Span::styled(
                                    "Vote Results:",
                                    Style::default().fg(Color::Cyan),
                                )),
                            ];

                            for voter in &summary.voters {
                                let voter_ss58 = format_account_ss58(&voter.0, ss58_prefix);
                                let vote_display = match summary.votes.get(voter) {
                                    None => Span::styled("Uncast", Style::default().fg(Color::DarkGray)),
                                    Some(VoteStatus::Committed(_)) => {
                                        Span::styled("Committed", Style::default().fg(Color::Yellow))
                                    }
                                    Some(VoteStatus::Revealed(Ok(vote))) => {
                                        let color = match vote {
                                            corevo_lib::CorevoVote::Aye => Color::Green,
                                            corevo_lib::CorevoVote::Nay => Color::Red,
                                            corevo_lib::CorevoVote::Abstain => Color::Blue,
                                        };
                                        Span::styled(format!("{:?}", vote), Style::default().fg(color))
                                    }
                                    Some(VoteStatus::Revealed(Err(_))) => {
                                        Span::styled("****** (unknown salt)", Style::default().fg(Color::DarkGray))
                                    }
                                    Some(VoteStatus::RevealedWithoutCommitment) => {
                                        Span::styled("Invalid", Style::default().fg(Color::Red))
                                    }
                                };

                                // Truncate address for display
                                let voter_short = if voter_ss58.len() > 16 {
                                    format!("{}..{}", &voter_ss58[..8], &voter_ss58[voter_ss58.len()-6..])
                                } else {
                                    voter_ss58
                                };

                                lines.push(Line::from(vec![
                                    Span::raw("  "),
                                    Span::styled(
                                        format!("{}: ", voter_short),
                                        Style::default().fg(Color::White),
                                    ),
                                    vote_display,
                                ]));
                            }

                            let details = Paragraph::new(lines).block(
                                Block::default()
                                    .title(format!("{}", ctx))
                                    .borders(Borders::ALL),
                            );
                            frame.render_widget(details, content_chunks[1]);
                        }
                    } else {
                        let empty = Paragraph::new("Select a context to view details")
                            .style(Style::default().fg(Color::DarkGray))
                            .block(Block::default().title("Details").borders(Borders::ALL));
                        frame.render_widget(empty, content_chunks[1]);
                    }
                } else {
                    let msg = Paragraph::new("No history data")
                        .block(Block::default().borders(Borders::ALL));
                    frame.render_widget(msg, chunks[2]);
                }
            }
        }

        // Help
        let help = Paragraph::new("Up/Down: Navigate | r: Refresh | Click address to copy | Esc: Back")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[3]);
    }

    fn render_account_pane(app: &App, frame: &mut Frame, area: ratatui::layout::Rect) {
        let _ss58_prefix = ss58_prefix_for_chain(&app.config_form.chain_url);

        // Check if announcing
        if matches!(app.announce_loading, LoadingState::Loading) {
            let content = Paragraph::new("Announcing public key to chain...")
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().title("My Account").borders(Borders::ALL));
            frame.render_widget(content, area);
            return;
        }

        if let LoadingState::Error(ref e) = app.announce_loading {
            let content = Paragraph::new(format!("Announce failed: {}", e))
                .style(Style::default().fg(Color::Red))
                .block(Block::default().title("My Account").borders(Borders::ALL));
            frame.render_widget(content, area);
            return;
        }

        let lines = if app.secret_uri.is_empty() {
            vec![
                Line::from(Span::styled(
                    "No account configured. Go to Config to set up.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        } else if let Some(addr) = &app.derived_address {
            let addr_short = if addr.len() > 24 {
                format!("{}...{}", &addr[..12], &addr[addr.len()-10..])
            } else {
                addr.clone()
            };

            // Show "Copied!" feedback if recently copied
            let copy_hint = if app.should_show_copied() {
                Span::styled(" (Copied!)", Style::default().fg(Color::Green))
            } else {
                Span::styled(" (click to copy)", Style::default().fg(Color::DarkGray))
            };

            let pubkey_status = match app.has_announced_pubkey() {
                Some(true) => Line::from(vec![
                    Span::styled("X25519 Pubkey: ", Style::default().fg(Color::Yellow)),
                    Span::styled("Announced ", Style::default().fg(Color::Green)),
                    Span::styled("(others can invite you to vote)", Style::default().fg(Color::DarkGray)),
                ]),
                Some(false) => Line::from(vec![
                    Span::styled("X25519 Pubkey: ", Style::default().fg(Color::Yellow)),
                    Span::styled("Not announced ", Style::default().fg(Color::Red)),
                    Span::styled("(go to Home to announce)", Style::default().fg(Color::DarkGray)),
                ]),
                None => Line::from(vec![
                    Span::styled("X25519 Pubkey: ", Style::default().fg(Color::Yellow)),
                    Span::styled("Loading...", Style::default().fg(Color::DarkGray)),
                ]),
            };

            vec![
                Line::from(vec![
                    Span::styled("Address: ", Style::default().fg(Color::Yellow)),
                    Span::styled(addr_short, Style::default().fg(Color::Green).add_modifier(Modifier::UNDERLINED)),
                    copy_hint,
                ]),
                pubkey_status,
            ]
        } else {
            vec![
                Line::from(Span::styled(
                    "Invalid account configuration",
                    Style::default().fg(Color::Red),
                )),
            ]
        };

        let content = Paragraph::new(lines)
            .block(Block::default().title("My Account").borders(Borders::ALL));
        frame.render_widget(content, area);
    }
}
