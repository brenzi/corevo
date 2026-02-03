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
                Constraint::Min(10),    // Content
                Constraint::Length(3),  // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Voting History")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // Content based on loading state
        match &app.history_loading {
            LoadingState::Idle => {
                let msg = Paragraph::new("Press Enter to load history")
                    .style(Style::default().fg(Color::DarkGray))
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(msg, chunks[1]);
            }
            LoadingState::Loading => {
                let msg = Paragraph::new("Loading history from indexer...")
                    .style(Style::default().fg(Color::Yellow))
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(msg, chunks[1]);
            }
            LoadingState::Error(e) => {
                let msg = Paragraph::new(format!("Error: {}", e))
                    .style(Style::default().fg(Color::Red))
                    .block(Block::default().borders(Borders::ALL));
                frame.render_widget(msg, chunks[1]);
            }
            LoadingState::Loaded => {
                if let Some(ref history) = app.history {
                    // Split content into list and details
                    let content_chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
                        .split(chunks[1]);

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
                            let mut lines = vec![
                                Line::from(vec![
                                    Span::styled("Proposer: ", Style::default().fg(Color::Yellow)),
                                    Span::raw(proposer_ss58),
                                ]),
                                Line::from(vec![
                                    Span::styled("Voters: ", Style::default().fg(Color::Yellow)),
                                    Span::raw(format!("{}", summary.voters.len())),
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
                                    Some(VoteStatus::Revealed(Err(e))) => {
                                        Span::styled(format!("Error: {}", e), Style::default().fg(Color::Red))
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
                    frame.render_widget(msg, chunks[1]);
                }
            }
        }

        // Help
        let help = Paragraph::new("Up/Down/j/k: Navigate | Scroll: Mouse wheel | r: Refresh | Esc: Back")
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[2]);
    }
}
