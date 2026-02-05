use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};

use crate::app::{App, LoadingState, ProposeField};
use corevo_lib::{format_account_ss58, ss58_prefix_for_chain};

pub struct ProposeComponent;

impl ProposeComponent {
    pub fn render(app: &App, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .margin(1)
            .constraints([
                Constraint::Length(3), // Title
                Constraint::Length(3), // Context name field
                Constraint::Length(5), // Common salt toggle (extra height for wrapping)
                Constraint::Min(5),    // Voter selection list
                Constraint::Length(3), // Create button
                Constraint::Length(3), // Status
                Constraint::Length(2), // Help (no borders, so 2 is enough)
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Create New Voting Context")
            .style(
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            )
            .block(Block::default().borders(Borders::BOTTOM));
        frame.render_widget(title, chunks[0]);

        // Context name field
        let name_focused = app.propose_form.focused_field == ProposeField::ContextName;
        let name_border_style = if name_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let name_field = Paragraph::new(Line::from(vec![
            Span::styled("Context Name: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                &app.propose_form.context_name,
                Style::default().fg(Color::Yellow),
            ),
            if name_focused {
                Span::styled(
                    "_",
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::SLOW_BLINK),
                )
            } else {
                Span::raw("")
            },
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(name_border_style)
                .title(if name_focused {
                    "Context Name (editing)"
                } else {
                    "Context Name"
                }),
        );
        frame.render_widget(name_field, chunks[1]);

        // Common salt toggle
        let salt_focused = app.propose_form.focused_field == ProposeField::UseCommonSalt;
        let salt_border_style = if salt_focused {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        let checkbox = if app.propose_form.use_common_salt {
            "[x]"
        } else {
            "[ ]"
        };
        let salt_checkbox_style = if app.propose_form.use_common_salt {
            Style::default().fg(Color::Green)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let salt_description = if app.propose_form.use_common_salt {
            "Hide votes from public (requires proposer key to reveal)"
        } else {
            "Votes publicly verifiable by anyone"
        };
        let salt_field = Paragraph::new(vec![
            Line::from(vec![
                Span::styled(checkbox, salt_checkbox_style),
                Span::styled(" Use group salt", Style::default().fg(Color::Cyan)),
            ]),
            Line::from(Span::styled(salt_description, Style::default().fg(Color::DarkGray))),
        ])
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(salt_border_style)
                .title(if salt_focused {
                    "Group Salt (Space to toggle)"
                } else {
                    "Group Salt"
                }),
        );
        frame.render_widget(salt_field, chunks[2]);

        // Voter selection list
        let ss58_prefix = ss58_prefix_for_chain(&app.config_form.chain_url);
        let selected_count = app
            .propose_form
            .available_voters
            .iter()
            .filter(|v| v.selected)
            .count();
        let voter_title = format!(
            "Select Voters ({} selected, {} available)",
            selected_count,
            app.propose_form.available_voters.len()
        );

        let voter_content: Vec<ListItem> = match &app.voters_loading {
            LoadingState::Loading => {
                vec![ListItem::new(Line::from(Span::styled(
                    "Loading available voters...",
                    Style::default().fg(Color::Yellow),
                )))]
            }
            LoadingState::Error(e) => {
                vec![ListItem::new(Line::from(Span::styled(
                    format!("Error: {}", e),
                    Style::default().fg(Color::Red),
                )))]
            }
            LoadingState::Idle | LoadingState::Loaded => {
                if app.propose_form.available_voters.is_empty() {
                    vec![ListItem::new(Line::from(Span::styled(
                        "No voters have announced their public keys yet.",
                        Style::default().fg(Color::DarkGray),
                    )))]
                } else {
                    app.propose_form
                        .available_voters
                        .iter()
                        .enumerate()
                        .map(|(i, voter)| {
                            let is_focused =
                                app.propose_form.focused_field == ProposeField::Voter(i);
                            let checkbox = if voter.selected { "[x]" } else { "[ ]" };
                            let address = format_account_ss58(&voter.account_id.0, ss58_prefix);

                            let style = if is_focused {
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
                            } else if voter.selected {
                                Style::default()
                                    .fg(Color::Green)
                                    .add_modifier(Modifier::UNDERLINED)
                            } else {
                                Style::default().add_modifier(Modifier::UNDERLINED)
                            };

                            let prefix = if is_focused { "> " } else { "  " };

                            ListItem::new(Line::from(vec![
                                Span::styled(prefix, Style::default().fg(Color::Yellow)),
                                Span::styled(
                                    checkbox,
                                    if voter.selected {
                                        Style::default().fg(Color::Green)
                                    } else {
                                        Style::default().fg(Color::DarkGray)
                                    },
                                ),
                                Span::raw(" "),
                                Span::styled(address, style),
                            ]))
                        })
                        .collect()
                }
            }
        };

        // Determine if a voter is focused and get the index for auto-scroll
        let focused_voter_index = match app.propose_form.focused_field {
            ProposeField::Voter(i) => Some(i),
            _ => None,
        };

        let voter_list = List::new(voter_content)
            .block(Block::default().borders(Borders::ALL).title(voter_title));

        // Use stateful rendering for auto-scroll when a voter is focused
        let mut list_state = ListState::default().with_selected(focused_voter_index);
        frame.render_stateful_widget(voter_list, chunks[3], &mut list_state);

        // Create button
        let button_focused = app.propose_form.focused_field == ProposeField::CreateButton;
        // When not using common salt, voters are optional (public context)
        let can_submit = app.derived_address.is_some()
            && !app.propose_form.context_name.is_empty()
            && (selected_count > 0 || !app.propose_form.use_common_salt)
            && app.propose_loading != LoadingState::Loading;

        let button_style = if button_focused {
            if can_submit {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Black).bg(Color::DarkGray)
            }
        } else if can_submit {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let button_text = if app.propose_loading == LoadingState::Loading {
            "  [ Submitting... ]  "
        } else if app.propose_form.use_common_salt {
            "  [ Create & Invite Voters ]  "
        } else {
            "  [ Create Public Context ]  "
        };

        let button = Paragraph::new(button_text)
            .style(button_style)
            .alignment(Alignment::Center)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(if button_focused {
                        Style::default().fg(Color::Yellow)
                    } else {
                        Style::default()
                    }),
            );
        frame.render_widget(button, chunks[4]);

        // Status
        let status_content = match &app.propose_loading {
            LoadingState::Loading => {
                let msg = if app.propose_form.use_common_salt {
                    "Creating context and sending invitations..."
                } else {
                    "Creating public context..."
                };
                vec![Line::from(Span::styled(
                    msg,
                    Style::default().fg(Color::Yellow),
                ))]
            }
            LoadingState::Error(e) => {
                vec![Line::from(Span::styled(
                    format!("Error: {}", e),
                    Style::default().fg(Color::Red),
                ))]
            }
            LoadingState::Loaded => {
                let msg = if app.propose_form.use_common_salt {
                    "Context created and invitations sent!"
                } else {
                    "Public context created!"
                };
                vec![Line::from(Span::styled(
                    msg,
                    Style::default().fg(Color::Green),
                ))]
            }
            LoadingState::Idle => {
                if app.derived_address.is_none() {
                    vec![Line::from(Span::styled(
                        "Warning: No account configured! Go to Config first.",
                        Style::default().fg(Color::Red),
                    ))]
                } else if app.propose_form.context_name.is_empty() {
                    vec![Line::from(Span::styled(
                        "Enter a context name above",
                        Style::default().fg(Color::DarkGray),
                    ))]
                } else if selected_count == 0 && app.propose_form.use_common_salt {
                    vec![Line::from(Span::styled(
                        "Select at least one voter to invite",
                        Style::default().fg(Color::Yellow),
                    ))]
                } else {
                    let mode = if app.propose_form.use_common_salt {
                        format!("{} voter(s)", selected_count)
                    } else {
                        "public".to_string()
                    };
                    vec![Line::from(vec![
                        Span::styled("Ready: ", Style::default().fg(Color::Green)),
                        Span::styled(
                            format!("\"{}\" ({})", app.propose_form.context_name, mode),
                            Style::default().fg(Color::White),
                        ),
                    ])]
                }
            }
        };

        let status = Paragraph::new(status_content)
            .block(Block::default().borders(Borders::ALL).title("Status"));
        frame.render_widget(status, chunks[5]);

        // Help
        let help_text = match app.propose_form.focused_field {
            ProposeField::ContextName => "Tab/Down: Next | Type: Edit name | Esc: Back",
            ProposeField::UseCommonSalt => "Space: Toggle | Tab/Up/Down: Navigate | Esc: Back",
            ProposeField::Voter(_) => {
                "Space/Enter: Toggle | Tab/Up/Down: Navigate | Ctrl+A: All | Esc: Back"
            }
            ProposeField::CreateButton => {
                if can_submit {
                    if app.propose_form.use_common_salt {
                        "Enter: Create & Send Invitations | Tab/Up: Back | Esc: Cancel"
                    } else {
                        "Enter: Create Public Context | Tab/Up: Back | Esc: Cancel"
                    }
                } else {
                    "Tab/Up: Back | Esc: Cancel"
                }
            }
        };
        let help = Paragraph::new(help_text)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[6]);
    }
}
