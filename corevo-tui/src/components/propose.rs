use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
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
                Constraint::Length(3),  // Title
                Constraint::Length(3),  // Context name field
                Constraint::Min(6),     // Voter selection list
                Constraint::Length(3),  // Create button
                Constraint::Length(3),  // Status
                Constraint::Length(3),  // Help
            ])
            .split(frame.area());

        // Title
        let title = Paragraph::new("Create New Voting Context")
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
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
            Span::styled(&app.propose_form.context_name, Style::default().fg(Color::Yellow)),
            if name_focused {
                Span::styled("_", Style::default().fg(Color::Yellow).add_modifier(Modifier::SLOW_BLINK))
            } else {
                Span::raw("")
            },
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(name_border_style)
                .title(if name_focused { "Context Name (editing)" } else { "Context Name" }),
        );
        frame.render_widget(name_field, chunks[1]);

        // Voter selection list
        let ss58_prefix = ss58_prefix_for_chain(&app.config_form.chain_url);
        let selected_count = app.propose_form.available_voters.iter().filter(|v| v.selected).count();
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
                            let is_focused = app.propose_form.focused_field == ProposeField::Voter(i);
                            let checkbox = if voter.selected { "[x]" } else { "[ ]" };
                            let address = format_account_ss58(&voter.account_id.0, ss58_prefix);

                            let style = if is_focused {
                                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
                            } else if voter.selected {
                                Style::default().fg(Color::Green)
                            } else {
                                Style::default()
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

        let voter_list = List::new(voter_content)
            .block(Block::default().borders(Borders::ALL).title(voter_title));
        frame.render_widget(voter_list, chunks[2]);

        // Create button
        let button_focused = app.propose_form.focused_field == ProposeField::CreateButton;
        let can_submit = app.derived_address.is_some()
            && !app.propose_form.context_name.is_empty()
            && selected_count > 0
            && app.propose_loading != LoadingState::Loading;

        let button_style = if button_focused {
            if can_submit {
                Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Black).bg(Color::DarkGray)
            }
        } else if can_submit {
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };

        let button_text = if app.propose_loading == LoadingState::Loading {
            "  [ Submitting... ]  "
        } else {
            "  [ Create & Invite Voters ]  "
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
        frame.render_widget(button, chunks[3]);

        // Status
        let status_content = match &app.propose_loading {
            LoadingState::Loading => {
                vec![Line::from(Span::styled(
                    "Generating common salt and sending invitations...",
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
                vec![Line::from(Span::styled(
                    "Context created and invitations sent successfully!",
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
                } else if selected_count == 0 {
                    vec![Line::from(Span::styled(
                        "Select at least one voter to invite",
                        Style::default().fg(Color::Yellow),
                    ))]
                } else {
                    vec![Line::from(vec![
                        Span::styled("Ready: ", Style::default().fg(Color::Green)),
                        Span::styled(
                            format!("\"{}\" with {} voter(s)", app.propose_form.context_name, selected_count),
                            Style::default().fg(Color::White),
                        ),
                    ])]
                }
            }
        };

        let status = Paragraph::new(status_content)
            .block(Block::default().borders(Borders::ALL).title("Status"));
        frame.render_widget(status, chunks[4]);

        // Help
        let help_text = match app.propose_form.focused_field {
            ProposeField::ContextName => "Tab/Down: Next | Type: Edit name | Esc: Back",
            ProposeField::Voter(_) => "Space/Enter: Toggle | Tab/Up/Down: Navigate | Ctrl+A: All | Esc: Back",
            ProposeField::CreateButton => {
                if can_submit {
                    "Enter: Create & Send Invitations | Tab/Up: Back | Esc: Cancel"
                } else {
                    "Tab/Up: Back | Esc: Cancel"
                }
            }
        };
        let help = Paragraph::new(help_text)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::TOP));
        frame.render_widget(help, chunks[5]);
    }
}
