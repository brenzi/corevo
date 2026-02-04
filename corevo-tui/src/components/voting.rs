use corevo_lib::VoteStatus;
use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph},
};

use crate::app::{App, LoadingState};

pub struct VotingComponent;

impl VotingComponent {
    pub fn render(app: &App, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Title
                Constraint::Length(6), // Context info
                Constraint::Min(10),   // Vote options or context selection
                Constraint::Length(3), // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Voting Session")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // Check if we have a selected context
        if let Some(ref ctx) = app.selected_context {
            // Context is selected - show voting interface based on vote status
            Self::render_voting_interface(app, frame, ctx, &chunks);
        } else {
            // No context selected - show context selection list
            Self::render_context_selection(app, frame, &chunks);
        }

        // Help text based on current state
        let help_text = if app.show_reveal_confirm {
            "Y/Enter: Confirm reveal | N/Esc: Cancel"
        } else if app.selected_context.is_some() {
            match app.get_current_vote_status() {
                None => "1/2/3: Select vote | Enter: Commit | Backspace: Back | Esc: Home",
                Some(VoteStatus::Committed(_)) => {
                    "Enter/R: Reveal vote | Backspace: Back | Esc: Home"
                }
                Some(VoteStatus::Revealed(_)) => "Backspace: Back to list | Esc: Home",
                _ => "Backspace: Back to list | Esc: Home",
            }
        } else {
            "Up/Down: Navigate | Enter: Select | r: Refresh | Backspace/Esc: Home"
        };
        let help = Paragraph::new(help_text)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[3]);
    }

    fn render_voting_interface(
        app: &App,
        frame: &mut Frame,
        ctx: &corevo_lib::CorevoContext,
        chunks: &[ratatui::layout::Rect],
    ) {
        // Context info with vote status
        let vote_status = app.get_current_vote_status();
        let status_line = match vote_status {
            None => Line::from(Span::styled(
                "Status: Ready to vote",
                Style::default().fg(Color::Yellow),
            )),
            Some(VoteStatus::Committed(_)) => Line::from(Span::styled(
                "Status: Vote committed (not yet revealed)",
                Style::default().fg(Color::Cyan),
            )),
            Some(VoteStatus::Revealed(Ok(vote))) => {
                let color = match vote {
                    corevo_lib::CorevoVote::Aye => Color::Green,
                    corevo_lib::CorevoVote::Nay => Color::Red,
                    corevo_lib::CorevoVote::Abstain => Color::Blue,
                };
                Line::from(vec![
                    Span::styled("Status: Revealed - ", Style::default().fg(Color::Green)),
                    Span::styled(
                        format!("{}", vote),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ])
            }
            Some(VoteStatus::Revealed(Err(e))) => Line::from(Span::styled(
                format!("Status: Reveal error - {}", e),
                Style::default().fg(Color::Red),
            )),
            Some(VoteStatus::RevealedWithoutCommitment) => Line::from(Span::styled(
                "Status: Invalid (revealed without commitment)",
                Style::default().fg(Color::Red),
            )),
        };

        let context_text = vec![
            Line::from(vec![
                Span::styled("Context: ", Style::default().fg(Color::Yellow)),
                Span::raw(format!("{}", ctx)),
            ]),
            Line::from(""),
            status_line,
        ];

        let context_info = Paragraph::new(context_text).block(
            Block::default()
                .title("Current Session")
                .borders(Borders::ALL),
        );
        frame.render_widget(context_info, chunks[1]);

        // Check loading state for vote operations
        if let LoadingState::Loading = app.voting_loading {
            let loading = Paragraph::new("Submitting transaction to chain...")
                .style(Style::default().fg(Color::Yellow))
                .block(Block::default().title("Processing").borders(Borders::ALL));
            frame.render_widget(loading, chunks[2]);
            return;
        }

        if let LoadingState::Error(ref e) = app.voting_loading {
            let error = Paragraph::new(format!("Error: {}\n\nPress any key to retry.", e))
                .style(Style::default().fg(Color::Red))
                .block(Block::default().title("Error").borders(Borders::ALL));
            frame.render_widget(error, chunks[2]);
            return;
        }

        // Show different UI based on vote status
        match vote_status {
            None => {
                // Not yet voted - show vote options
                Self::render_vote_options(app, frame, chunks);
            }
            Some(VoteStatus::Committed(_)) => {
                // Committed but not revealed - show reveal button
                Self::render_reveal_option(app, frame, chunks);
            }
            Some(VoteStatus::Revealed(Ok(vote))) => {
                // Already revealed - show the vote
                Self::render_revealed_vote(frame, chunks, vote);
            }
            Some(VoteStatus::Revealed(Err(e))) => {
                let error = Paragraph::new(format!(
                    "Your vote could not be verified.\n\nError: {}\n\nThis may happen if the commitment doesn't match any vote option.",
                    e
                ))
                .style(Style::default().fg(Color::Red))
                .block(Block::default().title("Verification Failed").borders(Borders::ALL));
                frame.render_widget(error, chunks[2]);
            }
            Some(VoteStatus::RevealedWithoutCommitment) => {
                let error = Paragraph::new(
                    "Invalid state: A reveal was recorded without a prior commitment.\n\nThis vote is invalid."
                )
                .style(Style::default().fg(Color::Red))
                .block(Block::default().title("Invalid Vote").borders(Borders::ALL));
                frame.render_widget(error, chunks[2]);
            }
        }
    }

    fn render_vote_options(app: &App, frame: &mut Frame, chunks: &[ratatui::layout::Rect]) {
        if app.secret_uri.is_empty() {
            let placeholder = Paragraph::new("Configure your account in Config to cast your vote")
                .style(Style::default().fg(Color::DarkGray))
                .block(
                    Block::default()
                        .title("Cast Your Vote")
                        .borders(Borders::ALL),
                );
            frame.render_widget(placeholder, chunks[2]);
            return;
        }

        let vote_options = [
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
            .block(
                Block::default()
                    .title("Cast Your Vote (Enter to commit)")
                    .borders(Borders::ALL),
            )
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
        frame.render_widget(menu, chunks[2]);
    }

    fn render_reveal_option(app: &App, frame: &mut Frame, chunks: &[ratatui::layout::Rect]) {
        // Check if showing confirmation dialog
        if app.show_reveal_confirm {
            let content = vec![
                Line::from(""),
                Line::from(Span::styled(
                    "Are you sure you want to reveal your vote?",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from("Once revealed, your vote will be visible to everyone."),
                Line::from("This action cannot be undone."),
                Line::from(""),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [Y] ", Style::default().fg(Color::Green)),
                    Span::raw("Yes, reveal my vote"),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("  [N] ", Style::default().fg(Color::Red)),
                    Span::raw("No, cancel"),
                ]),
            ];

            let confirm_dialog = Paragraph::new(content).block(
                Block::default()
                    .title("Confirm Reveal")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Yellow)),
            );
            frame.render_widget(confirm_dialog, chunks[2]);
            return;
        }

        let content = vec![
            Line::from(""),
            Line::from(Span::styled(
                "Your vote has been committed to the chain.",
                Style::default().fg(Color::Green),
            )),
            Line::from(""),
            Line::from("Your vote remains secret until you reveal it."),
            Line::from("Once revealed, everyone can verify your vote."),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    "[Enter/R] Reveal my vote to the group",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
        ];

        let reveal_info = Paragraph::new(content)
            .block(Block::default().title("Reveal Vote").borders(Borders::ALL));
        frame.render_widget(reveal_info, chunks[2]);
    }

    fn render_revealed_vote(
        frame: &mut Frame,
        chunks: &[ratatui::layout::Rect],
        vote: &corevo_lib::CorevoVote,
    ) {
        let (vote_str, color) = match vote {
            corevo_lib::CorevoVote::Aye => ("AYE", Color::Green),
            corevo_lib::CorevoVote::Nay => ("NAY", Color::Red),
            corevo_lib::CorevoVote::Abstain => ("ABSTAIN", Color::Blue),
        };

        let content = vec![
            Line::from(""),
            Line::from(Span::styled(
                "Your vote has been revealed!",
                Style::default().fg(Color::Green),
            )),
            Line::from(""),
            Line::from(""),
            Line::from(vec![
                Span::raw("  Your vote: "),
                Span::styled(
                    vote_str,
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(""),
            Line::from(""),
            Line::from(Span::styled(
                "Everyone can now verify your vote on-chain.",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let revealed_info = Paragraph::new(content).block(
            Block::default()
                .title("Vote Revealed")
                .borders(Borders::ALL),
        );
        frame.render_widget(revealed_info, chunks[2]);
    }

    fn render_context_selection(app: &App, frame: &mut Frame, chunks: &[ratatui::layout::Rect]) {
        // Show status/instructions in the context info area
        let status_text = if app.secret_uri.is_empty() {
            vec![
                Line::from(Span::styled(
                    "No account configured",
                    Style::default().fg(Color::Red),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    "Go to Config to set up your account first.",
                    Style::default().fg(Color::DarkGray),
                )),
            ]
        } else {
            match &app.history_loading {
                LoadingState::Idle => vec![Line::from(Span::styled(
                    "Press Enter or 'r' to load voting contexts",
                    Style::default().fg(Color::Yellow),
                ))],
                LoadingState::Loading => vec![Line::from(Span::styled(
                    "Loading voting contexts...",
                    Style::default().fg(Color::Yellow),
                ))],
                LoadingState::Error(e) => vec![
                    Line::from(Span::styled(
                        format!("Error: {}", e),
                        Style::default().fg(Color::Red),
                    )),
                    Line::from(""),
                    Line::from(Span::styled(
                        "Press 'r' to retry",
                        Style::default().fg(Color::DarkGray),
                    )),
                ],
                LoadingState::Loaded => {
                    if let Some(addr) = &app.derived_address {
                        let addr_short = if addr.len() > 20 {
                            format!("{}..{}", &addr[..10], &addr[addr.len() - 8..])
                        } else {
                            addr.clone()
                        };
                        let copy_hint = if app.should_show_copied() {
                            Span::styled(" (Copied!)", Style::default().fg(Color::Green))
                        } else {
                            Span::styled(" (click to copy)", Style::default().fg(Color::DarkGray))
                        };
                        vec![
                            Line::from(vec![
                                Span::styled("Account: ", Style::default().fg(Color::Yellow)),
                                Span::styled(
                                    addr_short,
                                    Style::default()
                                        .fg(Color::Green)
                                        .add_modifier(Modifier::UNDERLINED),
                                ),
                                copy_hint,
                            ]),
                            Line::from(""),
                            Line::from(Span::styled(
                                "Select a context below to cast your vote",
                                Style::default().fg(Color::Green),
                            )),
                        ]
                    } else {
                        vec![Line::from(Span::styled(
                            "Select a context below to cast your vote",
                            Style::default().fg(Color::Green),
                        ))]
                    }
                }
            }
        };

        let status_info = Paragraph::new(status_text)
            .block(Block::default().title("Status").borders(Borders::ALL));
        frame.render_widget(status_info, chunks[1]);

        // Show pending vote contexts
        if app.secret_uri.is_empty() {
            let placeholder =
                Paragraph::new("Configure your account to see available voting contexts")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(
                        Block::default()
                            .title("Pending Votes")
                            .borders(Borders::ALL),
                    );
            frame.render_widget(placeholder, chunks[2]);
            return;
        }

        match &app.history_loading {
            LoadingState::Idle => {
                let placeholder = Paragraph::new("Press Enter to load contexts")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(
                        Block::default()
                            .title("Pending Votes")
                            .borders(Borders::ALL),
                    );
                frame.render_widget(placeholder, chunks[2]);
            }
            LoadingState::Loading => {
                let placeholder = Paragraph::new("Loading...")
                    .style(Style::default().fg(Color::Yellow))
                    .block(
                        Block::default()
                            .title("Pending Votes")
                            .borders(Borders::ALL),
                    );
                frame.render_widget(placeholder, chunks[2]);
            }
            LoadingState::Error(_) => {
                let placeholder = Paragraph::new("Failed to load contexts")
                    .style(Style::default().fg(Color::Red))
                    .block(
                        Block::default()
                            .title("Pending Votes")
                            .borders(Borders::ALL),
                    );
                frame.render_widget(placeholder, chunks[2]);
            }
            LoadingState::Loaded => {
                let pending_contexts = app.get_pending_vote_contexts();

                if pending_contexts.is_empty() {
                    let placeholder = Paragraph::new(
                        "No pending votes found.\n\nYou may not be invited to any contexts,\nor you have already completed voting in all of them."
                    )
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().title("Pending Votes").borders(Borders::ALL));
                    frame.render_widget(placeholder, chunks[2]);
                } else {
                    // Get user's vote status for each context to show in list
                    let account_id = app.get_current_account_id().cloned();
                    let history = app.history.as_ref();

                    let items: Vec<ListItem> = pending_contexts
                        .iter()
                        .map(|ctx| {
                            // Determine status for this context
                            let status = if let (Some(acc), Some(hist)) = (&account_id, history) {
                                let hashable = corevo_lib::HashableAccountId::from(acc.clone());
                                hist.contexts
                                    .get(*ctx)
                                    .and_then(|summary| summary.votes.get(&hashable))
                            } else {
                                None
                            };

                            let (status_text, status_color) = match status {
                                None => ("[commit]", Color::Yellow),
                                Some(VoteStatus::Committed(_)) => ("[reveal]", Color::Cyan),
                                _ => ("", Color::White),
                            };

                            ListItem::new(Line::from(vec![
                                Span::styled("  ", Style::default()),
                                Span::raw(format!("{}", ctx)),
                                Span::raw(" "),
                                Span::styled(status_text, Style::default().fg(status_color)),
                            ]))
                        })
                        .collect();

                    let list = List::new(items)
                        .block(
                            Block::default()
                                .title(format!("Pending Votes ({})", pending_contexts.len()))
                                .borders(Borders::ALL),
                        )
                        .highlight_style(
                            Style::default()
                                .fg(Color::Yellow)
                                .add_modifier(Modifier::BOLD | Modifier::REVERSED),
                        )
                        .highlight_symbol("> ");

                    let mut list_state = ListState::default();
                    list_state.select(Some(
                        app.selected_index
                            .min(pending_contexts.len().saturating_sub(1)),
                    ));
                    frame.render_stateful_widget(list, chunks[2], &mut list_state);
                }
            }
        }
    }
}
