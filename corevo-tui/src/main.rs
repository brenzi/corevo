mod action;
mod app;
mod components;
mod event;
mod tui;

use std::time::Duration;

use color_eyre::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use tokio::sync::mpsc;

use action::Action;
use app::{App, LoadingState, Screen};
use components::{
    config::ConfigComponent, history::HistoryComponent, home::HomeComponent,
    propose::ProposeComponent, voting::VotingComponent,
};
use event::{Event, EventHandler};
use tui::Tui;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    // Set up file logging to avoid interfering with TUI
    if std::env::var("RUST_LOG").is_ok() {
        use std::io::Write;
        if let Ok(log_file) = std::fs::File::create("corevo-tui.log") {
            env_logger::Builder::from_default_env()
                .format(|buf, record| {
                    writeln!(
                        buf,
                        "[{}] {}:{} - {}",
                        record.level(),
                        record.file().unwrap_or("unknown"),
                        record.line().unwrap_or(0),
                        record.args()
                    )
                })
                .target(env_logger::Target::Pipe(Box::new(log_file)))
                .init();
        }
    }

    // Create action channel
    let (action_tx, mut action_rx) = mpsc::unbounded_channel::<Action>();

    // Initialize app state
    let mut app = App::new(action_tx.clone());

    // Initialize TUI
    let mut tui = Tui::new()?;
    tui.enter()?;

    // Start event handler
    let mut events = EventHandler::new(Duration::from_millis(250));

    // Main event loop
    loop {
        // Draw UI
        tui.draw(|frame| match app.screen {
            Screen::Home => HomeComponent::render(&app, frame),
            Screen::History => HistoryComponent::render(&app, frame),
            Screen::Voting => VotingComponent::render(&app, frame),
            Screen::Config => ConfigComponent::render(&app, frame),
            Screen::Propose => ProposeComponent::render(&app, frame),
        })?;

        // Handle events and actions
        tokio::select! {
            // Terminal events
            Some(event) = events.next() => {
                for action in handle_event(&app, event) {
                    action_tx.send(action)?;
                }
            }

            // Actions from async operations
            Some(action) = action_rx.recv() => {
                // Handle special async actions
                match &action {
                    Action::LoadHistory => {
                        let config = app.config.clone();
                        let secret_uri = if app.secret_uri.is_empty() {
                            None
                        } else {
                            Some(app.secret_uri.clone())
                        };
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = load_history(&config, secret_uri.as_deref()).await;
                            let _ = tx.send(Action::HistoryLoaded(result));
                        });
                    }
                    Action::LoadBalance => {
                        if app.derived_address.is_some() {
                            let chain_url = app.config_form.chain_url.clone();
                            let secret_uri = app.secret_uri.clone();
                            // Capture the ID that will be set after handle_action increments it
                            let request_id = app.balance_request_id.wrapping_add(1);
                            let tx = action_tx.clone();
                            tokio::spawn(async move {
                                let result = load_balance_with_retry(&chain_url, &secret_uri).await;
                                let _ = tx.send(Action::BalanceLoaded(request_id, result));
                            });
                        }
                    }
                    Action::ProposeContext => {
                        let chain_url = app.config_form.chain_url.clone();
                        let secret_uri = app.secret_uri.clone();
                        let context_name = app.propose_form.context_name.clone();
                        let use_common_salt = app.propose_form.use_common_salt;
                        let selected_voters: Vec<_> = app.propose_form.available_voters
                            .iter()
                            .filter(|v| v.selected)
                            .map(|v| (v.account_id.clone(), v.pubkey))
                            .collect();
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = propose_context(&chain_url, &secret_uri, &context_name, &selected_voters, use_common_salt).await;
                            let _ = tx.send(Action::ProposeSubmitted(result));
                        });
                    }
                    Action::LoadVoters => {
                        let config = app.config.clone();
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = load_available_voters(&config).await;
                            let _ = tx.send(Action::VotersLoaded(result));
                        });
                    }
                    Action::CommitVote(vote) => {
                        let chain_url = app.config_form.chain_url.clone();
                        let secret_uri = app.secret_uri.clone();
                        let context = app.selected_context.clone();
                        let config = app.config.clone();
                        let vote = *vote;
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = commit_vote(&chain_url, &secret_uri, context, vote, &config).await;
                            let _ = tx.send(Action::CommitVoteResult(result));
                        });
                    }
                    Action::ConfirmReveal => {
                        let chain_url = app.config_form.chain_url.clone();
                        let secret_uri = app.secret_uri.clone();
                        let context = app.selected_context.clone();
                        let config = app.config.clone();
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = reveal_vote(&chain_url, &secret_uri, context, &config).await;
                            let _ = tx.send(Action::RevealVoteResult(result));
                        });
                    }
                    Action::AnnouncePubkey => {
                        let chain_url = app.config_form.chain_url.clone();
                        let secret_uri = app.secret_uri.clone();
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = announce_pubkey(&chain_url, &secret_uri).await;
                            let _ = tx.send(Action::AnnouncePubkeyResult(result));
                        });
                    }
                    _ => {}
                }

                app.handle_action(action);
            }
        }

        // Check if we should quit
        if app.should_quit {
            break;
        }
    }

    // Cleanup
    events.stop();
    tui.exit()?;

    Ok(())
}

/// Convert terminal events to actions
fn handle_event(app: &App, event: Event) -> Vec<Action> {
    match event {
        Event::Tick => vec![Action::Tick],
        Event::Key(key) => {
            let actions: Vec<_> = handle_key_event(app, key).into_iter().collect();
            for action in &actions {
                if is_loggable_action(action) {
                    log::info!("[{:?}] {:?}", app.screen, action);
                }
            }
            actions
        }
        Event::Mouse(mouse) => {
            let actions = handle_mouse_event(app, mouse);
            for action in &actions {
                if is_loggable_action(action) {
                    log::info!("[{:?}] {:?}", app.screen, action);
                }
            }
            actions
        }
        Event::Resize(_, _) => vec![Action::Render],
    }
}

/// Check if an action is worth logging (excludes navigation, input, and internal actions)
fn is_loggable_action(action: &Action) -> bool {
    !matches!(
        action,
        Action::Tick
            | Action::Render
            | Action::SelectPrev
            | Action::SelectNext
            | Action::SelectIndex(_)
            | Action::ScrollUp(_)
            | Action::ScrollDown(_)
            | Action::InputChar(_)
            | Action::InputBackspace
            | Action::InputDelete
            | Action::InputClear
            | Action::InputPaste(_)
            | Action::NextConfigField
            | Action::PrevConfigField
            | Action::NextProposeField
            | Action::PrevProposeField
            | Action::RecordClick(_, _)
            | Action::ClearCopiedFeedback
            | Action::CopiedFeedback
    )
}

/// Handle keyboard events based on current screen
fn handle_key_event(app: &App, key: KeyEvent) -> Option<Action> {
    // Global key bindings
    match key.code {
        KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            return Some(Action::Quit);
        }
        _ => {}
    }

    // Screen-specific key bindings
    match app.screen {
        Screen::Home => handle_home_keys(app, key),
        Screen::History => handle_history_keys(app, key),
        Screen::Voting => handle_voting_keys(app, key),
        Screen::Config => handle_config_keys(app, key),
        Screen::Propose => handle_propose_keys(app, key),
    }
}

fn handle_home_keys(app: &App, key: KeyEvent) -> Option<Action> {
    // If announce is loading/loaded/error, allow Esc to clear it
    if !matches!(app.announce_loading, LoadingState::Idle) {
        if matches!(key.code, KeyCode::Esc | KeyCode::Enter) {
            return Some(Action::ClearAnnounceState);
        }
        return None; // Block other keys while popup is showing
    }

    // Check if account can perform on-chain actions
    let can_use_chain = app.is_account_on_chain() == Some(true);
    let can_announce = can_use_chain && app.has_announced_pubkey() == Some(false);

    match key.code {
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char('1') => Some(Action::NavigateHistory),
        KeyCode::Char('2') => {
            if can_use_chain {
                Some(Action::NavigateVoting)
            } else {
                None
            }
        }
        KeyCode::Char('3') => {
            if can_use_chain {
                Some(Action::NavigatePropose)
            } else {
                None
            }
        }
        KeyCode::Char('4') => Some(Action::NavigateConfig),
        KeyCode::Char('5') => {
            if can_announce {
                Some(Action::AnnouncePubkey)
            } else {
                None
            }
        }
        // Skip disabled items when navigating
        KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectIndex(
            app.prev_enabled_home_item(app.selected_index),
        )),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectIndex(
            app.next_enabled_home_item(app.selected_index),
        )),
        KeyCode::Enter => match app.selected_index {
            0 => Some(Action::NavigateHistory),
            1 => {
                if can_use_chain {
                    Some(Action::NavigateVoting)
                } else {
                    None
                }
            }
            2 => {
                if can_use_chain {
                    Some(Action::NavigatePropose)
                } else {
                    None
                }
            }
            3 => Some(Action::NavigateConfig),
            4 => {
                if can_announce {
                    Some(Action::AnnouncePubkey)
                } else {
                    None
                }
            }
            5 => Some(Action::Quit),
            _ => None,
        },
        KeyCode::Esc => Some(Action::ClearError),
        _ => None,
    }
}

fn handle_history_keys(app: &App, key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::NavigateHome),
        KeyCode::Char('r') => Some(Action::LoadHistory),
        KeyCode::Enter => {
            // Load history if not yet loaded
            if app.history_loading == LoadingState::Idle {
                Some(Action::LoadHistory)
            } else {
                // Already loaded - Enter just confirms selection (details shown on right)
                None
            }
        }
        KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectPrev),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectNext),
        KeyCode::PageUp => Some(Action::ScrollUp(10)),
        KeyCode::PageDown => Some(Action::ScrollDown(10)),
        KeyCode::Home => Some(Action::SelectIndex(0)),
        KeyCode::End => {
            let max = app.get_list_length();
            if max > 0 {
                Some(Action::SelectIndex(max - 1))
            } else {
                None
            }
        }
        _ => None,
    }
}

fn handle_voting_keys(app: &App, key: KeyEvent) -> Option<Action> {
    use corevo_lib::VoteStatus;

    // If showing reveal confirmation dialog
    if app.show_reveal_confirm {
        return match key.code {
            KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => Some(Action::ConfirmReveal),
            KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc | KeyCode::Backspace => {
                Some(Action::CancelReveal)
            }
            _ => None,
        };
    }

    // If in loading state, allow Esc to go back
    if matches!(app.voting_loading, LoadingState::Loading) {
        return match key.code {
            KeyCode::Esc => Some(Action::NavigateHome),
            _ => None,
        };
    }

    // If in error state, allow any key to clear and retry, or Esc/Backspace to go back
    if matches!(app.voting_loading, LoadingState::Error(_)) {
        return match key.code {
            KeyCode::Esc => Some(Action::NavigateHome),
            KeyCode::Backspace => Some(Action::SelectContext(None)),
            _ => None, // Any other key could retry
        };
    }

    // Different behavior based on whether a context is selected
    if app.selected_context.is_some() {
        // Check vote status to determine behavior
        let vote_status = app.get_current_vote_status();

        match vote_status {
            None => {
                // Not yet voted - can select and commit a vote
                match key.code {
                    KeyCode::Esc => Some(Action::NavigateHome),
                    KeyCode::Backspace => Some(Action::SelectContext(None)),
                    KeyCode::Char('1') => Some(Action::SelectIndex(0)),
                    KeyCode::Char('2') => Some(Action::SelectIndex(1)),
                    KeyCode::Char('3') => Some(Action::SelectIndex(2)),
                    KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectPrev),
                    KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectNext),
                    KeyCode::Enter => {
                        // Commit the selected vote
                        let vote = match app.selected_index {
                            0 => corevo_lib::CorevoVote::Aye,
                            1 => corevo_lib::CorevoVote::Nay,
                            _ => corevo_lib::CorevoVote::Abstain,
                        };
                        Some(Action::CommitVote(vote))
                    }
                    _ => None,
                }
            }
            Some(VoteStatus::Committed(_)) => {
                // Committed but not revealed - show reveal button
                match key.code {
                    KeyCode::Esc => Some(Action::NavigateHome),
                    KeyCode::Backspace => Some(Action::SelectContext(None)),
                    KeyCode::Enter | KeyCode::Char('r') | KeyCode::Char('R') => {
                        Some(Action::ShowRevealConfirm)
                    }
                    _ => None,
                }
            }
            Some(VoteStatus::Revealed(_)) | Some(VoteStatus::RevealedWithoutCommitment) => {
                // Already revealed or invalid - can only go back
                match key.code {
                    KeyCode::Esc => Some(Action::NavigateHome),
                    KeyCode::Backspace => Some(Action::SelectContext(None)),
                    _ => None,
                }
            }
        }
    } else {
        // No context selected - context selection mode
        match key.code {
            KeyCode::Esc => Some(Action::NavigateHome),
            KeyCode::Backspace => Some(Action::NavigateHome),
            KeyCode::Char('r') => Some(Action::LoadHistory), // Refresh
            KeyCode::Enter => {
                // Load history if not yet loaded
                if app.history_loading == LoadingState::Idle {
                    Some(Action::LoadHistory)
                } else if app.history_loading == LoadingState::Loaded {
                    // Select the highlighted context
                    let pending = app.get_pending_vote_contexts();
                    pending
                        .get(app.selected_index)
                        .map(|ctx| Action::SelectContext(Some((*ctx).clone())))
                } else {
                    None
                }
            }
            KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectPrev),
            KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectNext),
            KeyCode::PageUp => Some(Action::ScrollUp(10)),
            KeyCode::PageDown => Some(Action::ScrollDown(10)),
            _ => None,
        }
    }
}

fn handle_config_keys(_app: &App, key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::NavigateHome),
        KeyCode::Tab => Some(Action::NextConfigField),
        KeyCode::BackTab => Some(Action::PrevConfigField),
        KeyCode::Up => Some(Action::PrevConfigField),
        KeyCode::Down => Some(Action::NextConfigField),
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(Action::SaveConfig)
        }
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(Action::InputClear)
        }
        KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            // Paste from clipboard
            if let Ok(mut clipboard) = arboard::Clipboard::new()
                && let Ok(text) = clipboard.get_text()
            {
                // Clean the text - remove newlines, trim whitespace
                let clean_text = text.trim().replace(['\n', '\r'], "");
                if !clean_text.is_empty() {
                    return Some(Action::InputPaste(clean_text));
                }
            }
            None
        }
        KeyCode::Char(c) => Some(Action::InputChar(c)),
        KeyCode::Backspace => Some(Action::InputBackspace),
        KeyCode::Delete => Some(Action::InputDelete),
        _ => None,
    }
}

fn handle_propose_keys(app: &App, key: KeyEvent) -> Option<Action> {
    use crate::app::ProposeField;

    let selected_count = app
        .propose_form
        .available_voters
        .iter()
        .filter(|v| v.selected)
        .count();
    let can_submit = app.derived_address.is_some()
        && !app.propose_form.context_name.is_empty()
        && selected_count > 0;

    match key.code {
        KeyCode::Esc => Some(Action::NavigateHome),
        KeyCode::Tab => Some(Action::NextProposeField),
        KeyCode::BackTab => Some(Action::PrevProposeField),
        KeyCode::Down => Some(Action::NextProposeField),
        KeyCode::Up => Some(Action::PrevProposeField),

        // Space toggles voter selection or activates button
        KeyCode::Char(' ') => match app.propose_form.focused_field {
            ProposeField::ContextName => Some(Action::InputChar(' ')),
            ProposeField::UseCommonSalt => Some(Action::ToggleUseCommonSalt),
            ProposeField::Voter(idx) => Some(Action::ToggleVoter(idx)),
            ProposeField::CreateButton if can_submit => Some(Action::ProposeContext),
            _ => None,
        },

        // Enter toggles voter or activates button
        KeyCode::Enter => match app.propose_form.focused_field {
            ProposeField::UseCommonSalt => Some(Action::ToggleUseCommonSalt),
            ProposeField::Voter(idx) => Some(Action::ToggleVoter(idx)),
            ProposeField::CreateButton if can_submit => Some(Action::ProposeContext),
            _ => None,
        },

        // Ctrl+S always submits if valid
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if can_submit {
                Some(Action::ProposeContext)
            } else {
                None
            }
        }

        // Ctrl+U clears current field
        KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if matches!(app.propose_form.focused_field, ProposeField::ContextName) {
                Some(Action::InputClear)
            } else {
                None
            }
        }

        // Ctrl+V pastes (only in name field)
        KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if matches!(app.propose_form.focused_field, ProposeField::ContextName)
                && let Ok(mut clipboard) = arboard::Clipboard::new()
                && let Ok(text) = clipboard.get_text()
            {
                let clean_text = text.trim().replace(['\n', '\r'], "");
                if !clean_text.is_empty() {
                    return Some(Action::InputPaste(clean_text));
                }
            }
            None
        }

        // Ctrl+A selects all voters
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(Action::SelectAllVoters)
        }

        // Text input only in name field
        KeyCode::Char(c) => {
            if matches!(app.propose_form.focused_field, ProposeField::ContextName) {
                Some(Action::InputChar(c))
            } else {
                None
            }
        }
        KeyCode::Backspace => {
            if matches!(app.propose_form.focused_field, ProposeField::ContextName) {
                Some(Action::InputBackspace)
            } else {
                None
            }
        }
        KeyCode::Delete => {
            if matches!(app.propose_form.focused_field, ProposeField::ContextName) {
                Some(Action::InputDelete)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Handle mouse events - returns actions to execute
fn handle_mouse_event(app: &App, mouse: MouseEvent) -> Vec<Action> {
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => handle_mouse_click(app, mouse.row, mouse.column),
        // Scroll wheel navigation - skip disabled items on home screen
        MouseEventKind::ScrollUp => {
            if app.screen == Screen::Home {
                vec![Action::SelectIndex(
                    app.prev_enabled_home_item(app.selected_index),
                )]
            } else {
                vec![Action::SelectPrev]
            }
        }
        MouseEventKind::ScrollDown => {
            if app.screen == Screen::Home {
                vec![Action::SelectIndex(
                    app.next_enabled_home_item(app.selected_index),
                )]
            } else {
                vec![Action::SelectNext]
            }
        }
        _ => vec![],
    }
}

/// Handle mouse click based on screen and position
fn handle_mouse_click(app: &App, row: u16, col: u16) -> Vec<Action> {
    let is_double = app.is_double_click(row, col);
    let mut actions = vec![];

    match app.screen {
        Screen::Home => {
            // Home screen layout: margin(2), title(3), info box(9), menu
            // Info box starts at row 2+3 = 5 (with border at row 5, content starts at row 6)
            // Account line is at row 5 + 1 (border) + 3 (chain, db, blank) = row 9
            let r = row as usize;
            let info_start = 2 + 3; // margin + title
            let account_row = info_start + 1 + 3; // border + chain + db + blank

            // Check if click is on account line (to copy address)
            if r == account_row
                && let Some(ref address) = app.derived_address
            {
                actions.push(Action::CopyAddress(address.clone()));
                return actions;
            }

            // Menu starts after info box
            let menu_start = 2 + 3 + 9 + 1; // margin + title + info + border
            // Items: History(0), Voting(1), Propose(2), Config(3), Announce(4), Quit(5)
            if r >= menu_start && r < menu_start + 6 {
                let idx = r - menu_start;
                let can_use_chain = app.is_account_on_chain() == Some(true);
                let can_announce = can_use_chain && app.has_announced_pubkey() == Some(false);

                if is_double {
                    // Double-click: navigate directly (respecting disabled states)
                    match idx {
                        0 => actions.push(Action::NavigateHistory),
                        1 => {
                            if can_use_chain {
                                actions.push(Action::NavigateVoting);
                            }
                        }
                        2 => {
                            if can_use_chain {
                                actions.push(Action::NavigatePropose);
                            }
                        }
                        3 => actions.push(Action::NavigateConfig),
                        4 => {
                            if can_announce {
                                actions.push(Action::AnnouncePubkey);
                            }
                        }
                        5 => actions.push(Action::Quit),
                        _ => {}
                    }
                } else {
                    // Single click: just select
                    actions.push(Action::SelectIndex(idx));
                }
            }
        }
        Screen::History => {
            // History layout: margin(1), title(3), account pane(6), content area
            // Account pane starts at row 1+3 = 4 (with border, content at row 5)
            // Address line is at row 4 + 1 = 5 (border + first line)
            let r = row as usize;
            let account_pane_start = 1 + 3; // margin + title
            let account_address_row = account_pane_start + 1; // border + content

            // Check if click is on account address line (to copy)
            if r == account_address_row
                && let Some(ref address) = app.derived_address
            {
                actions.push(Action::CopyAddress(address.clone()));
                return actions;
            }

            // Content area: list on left (40%) with border
            // List items start at row: 1 + 3 + 6 + 1 (margin + title + account pane + list border) = 11
            let list_start = 1 + 3 + 6 + 1;
            let max = app.get_list_length();
            if r >= list_start && max > 0 {
                let idx = r - list_start;
                if idx < max {
                    actions.push(Action::SelectIndex(idx));
                }
            }
        }
        Screen::Voting => {
            // Voting layout: margin(1), title(3), status/context(6), vote options
            // Status/context area: row 4-9 (with border at 4, content at 5)
            // If in context selection mode, account line is at row 5
            let r = row as usize;
            let status_area_start = 1 + 3; // margin + title
            let account_row = status_area_start + 1; // border + first content line

            // Check if click is on account line (to copy) - only in context selection mode
            if app.selected_context.is_none()
                && r == account_row
                && let Some(ref address) = app.derived_address
            {
                actions.push(Action::CopyAddress(address.clone()));
                return actions;
            }

            // Vote options have border, items start at row: 1+3+6+1 = 11
            let options_start = 1 + 3 + 6 + 1;
            if r >= options_start && r < options_start + 3 {
                let idx = r - options_start;
                actions.push(Action::SelectIndex(idx));
            }
        }
        Screen::Config => {
            // Config layout: margin(1), title(3), form fields
            // Each field is 3 rows (with border), starting at row 4
            let form_start = 1 + 3;
            let r = row as usize;
            if r >= form_start {
                let field_idx = (r - form_start) / 3;
                if field_idx < 4 {
                    actions.push(Action::SelectIndex(field_idx));
                }
            }
        }
        Screen::Propose => {
            // Propose layout: margin(1), title(3), context name(3), voter list(min 6), button(3), status(3), help(3)
            // Voter list starts at row: 1 + 3 + 3 = 7, with border so content starts at row 8
            let r = row as usize;
            let voter_list_start = 1 + 3 + 3 + 1; // margin + title + context name + border

            // Check if click is in the voter list area
            let ss58_prefix = corevo_lib::ss58_prefix_for_chain(&app.config_form.chain_url);
            if r >= voter_list_start && !app.propose_form.available_voters.is_empty() {
                let voter_idx = r - voter_list_start;
                if voter_idx < app.propose_form.available_voters.len() {
                    // Get the voter's full address for copying
                    let address = corevo_lib::format_account_ss58(
                        &app.propose_form.available_voters[voter_idx].account_id.0,
                        ss58_prefix,
                    );
                    actions.push(Action::CopyAddress(address));
                    return actions;
                }
            }
        }
    }

    // Always record the click for double-click detection
    actions.push(Action::RecordClick(row, col));
    actions
}

/// Async function to load history from indexer
async fn load_history(
    config: &corevo_lib::Config,
    secret_uri: Option<&str>,
) -> Result<corevo_lib::VotingHistory, String> {
    let mut query = corevo_lib::HistoryQuery::new(config);

    // If we have a secret URI, derive the account for decryption
    if let Some(uri) = secret_uri
        && !uri.is_empty()
        && let Ok(account) = corevo_lib::derive_account_from_uri(uri)
    {
        query = query.with_known_accounts(vec![account]);
    }

    query.execute().await.map_err(|e| e.to_string())
}

/// Async function to load account balance from chain with retry logic
async fn load_balance_with_retry(chain_url: &str, secret_uri: &str) -> Result<u128, String> {
    const MAX_RETRIES: u32 = 3;
    const RETRY_DELAY_MS: u64 = 500;

    let mut last_error = String::new();

    for attempt in 0..MAX_RETRIES {
        match load_balance(chain_url, secret_uri).await {
            Ok(balance) => return Ok(balance),
            Err(e) => {
                last_error = e;
                if attempt + 1 < MAX_RETRIES {
                    tokio::time::sleep(std::time::Duration::from_millis(
                        RETRY_DELAY_MS * (attempt as u64 + 1),
                    ))
                    .await;
                }
            }
        }
    }

    Err(last_error)
}

/// Async function to load account balance from chain
async fn load_balance(chain_url: &str, secret_uri: &str) -> Result<u128, String> {
    use corevo_lib::{ChainClient, derive_account_from_uri};

    // Derive account to get the account ID
    let account = derive_account_from_uri(secret_uri).map_err(|e| e.to_string())?;
    let account_id = account.sr25519_keypair.public_key().to_account_id();

    // Connect to chain and fetch balance
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    client
        .get_account_balance(&account_id)
        .await
        .map_err(|e| e.to_string())
}

/// Async function to load available voters (accounts with announced X25519 pubkeys)
async fn load_available_voters(
    config: &corevo_lib::Config,
) -> Result<Vec<crate::app::AvailableVoter>, String> {
    use crate::app::AvailableVoter;
    use corevo_lib::HistoryQuery;

    let history = HistoryQuery::new(config)
        .execute()
        .await
        .map_err(|e| e.to_string())?;

    let voters: Vec<AvailableVoter> = history
        .voter_pubkeys
        .into_iter()
        .map(|(account_id, pubkey)| AvailableVoter {
            account_id,
            pubkey,
            selected: false,
        })
        .collect();

    Ok(voters)
}

/// Async function to create a new voting context and invite selected voters
async fn propose_context(
    chain_url: &str,
    secret_uri: &str,
    context_name: &str,
    selected_voters: &[(
        corevo_lib::HashableAccountId,
        corevo_lib::PublicKeyForEncryption,
    )],
    use_common_salt: bool,
) -> Result<(), String> {
    use corevo_lib::{
        ChainClient, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1,
        PrefixedCorevoRemark, derive_account_from_uri, encrypt_for_recipient,
    };
    use rand::{RngCore, thread_rng};
    use x25519_dalek::PublicKey as X25519PublicKey;

    // Derive account for signing and encryption
    let account = derive_account_from_uri(secret_uri).map_err(|e| e.to_string())?;

    // Create the context - use Bytes if hex string, otherwise String
    let context = if context_name.starts_with("0x") || context_name.starts_with("0X") {
        // Try to parse as hex using corevo_lib's decode_hex
        match corevo_lib::primitives::decode_hex(context_name) {
            Ok(bytes) => CorevoContext::Bytes(bytes),
            Err(_) => CorevoContext::String(context_name.to_string()), // Fall back to string if invalid hex
        }
    } else {
        CorevoContext::String(context_name.to_string())
    };

    // Connect to chain
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    // Build all remarks in a batch for proper nonce sequencing
    let mut remarks = Vec::new();

    // Step 1: Announce proposer's X25519 public key in this context
    let pubkey_bytes: [u8; 32] = account.x25519_public.to_bytes();
    let announce_msg = CorevoMessage::AnnounceOwnPubKey(pubkey_bytes);
    remarks.push(PrefixedCorevoRemark::from(CorevoRemark::V1(
        CorevoRemarkV1 {
            context: context.clone(),
            msg: announce_msg,
        },
    )));

    // Step 2 & 3: Invite each selected voter
    // If using common salt, generate and encrypt it for each voter
    // If not using common salt, send empty encrypted_salt (public context)
    let common_salt: Option<[u8; 32]> = if use_common_salt {
        let mut salt = [0u8; 32];
        thread_rng().fill_bytes(&mut salt);
        Some(salt)
    } else {
        None
    };

    for (voter_account_id, voter_pubkey_bytes) in selected_voters {
        let encrypted_salt = if let Some(salt) = common_salt {
            let voter_pubkey = X25519PublicKey::from(*voter_pubkey_bytes);
            encrypt_for_recipient(&account.x25519_secret, &voter_pubkey, &salt)
                .map_err(|e| format!("Failed to encrypt for voter: {}", e))?
        } else {
            // Public context - no encrypted salt
            vec![]
        };

        let invite_msg = CorevoMessage::InviteVoter(voter_account_id.0.clone(), encrypted_salt);
        remarks.push(PrefixedCorevoRemark::from(CorevoRemark::V1(
            CorevoRemarkV1 {
                context: context.clone(),
                msg: invite_msg,
            },
        )));
    }

    // Send all remarks with proper nonce sequencing
    client
        .send_remarks_batch(&account.sr25519_keypair, remarks)
        .await
        .map_err(|e| format!("Failed to send remarks: {}", e))?;

    Ok(())
}

/// Async function to commit a vote to the chain
async fn commit_vote(
    chain_url: &str,
    secret_uri: &str,
    context: Option<corevo_lib::CorevoContext>,
    vote: corevo_lib::CorevoVote,
    config: &corevo_lib::Config,
) -> Result<(), String> {
    use codec::{Decode, Encode};
    #[allow(unused_imports)]
    use corevo_lib::Salt;
    use corevo_lib::{
        ChainClient, CorevoMessage, CorevoRemark, CorevoRemarkV1, CorevoVoteAndSalt,
        HashableAccountId, HistoryQuery, PrefixedCorevoRemark, decrypt_from_sender,
        derive_account_from_uri, encrypt_for_recipient, format_account_ss58, ss58_prefix_for_chain,
    };
    use futures::TryStreamExt;
    use mongodb::{
        Client,
        bson::{Bson, Document, doc},
        options::ClientOptions,
    };
    use rand::{RngCore, thread_rng};
    use x25519_dalek::PublicKey as X25519PublicKey;

    let context = context.ok_or("No voting context selected")?;

    // Derive account for signing and encryption
    let account = derive_account_from_uri(secret_uri).map_err(|e| e.to_string())?;
    let my_account_id = account.sr25519_keypair.public_key().to_account_id();

    // First try: Query history to see if common salt is already decrypted (works if we're the proposer)
    let account_for_query = derive_account_from_uri(secret_uri).map_err(|e| e.to_string())?;

    let full_history = HistoryQuery::new(config)
        .with_context(context.clone())
        .with_known_accounts(vec![account_for_query])
        .execute()
        .await
        .map_err(|e| e.to_string())?;

    // Try to get the common salt - might be empty for public contexts or if we're not the proposer
    let maybe_common_salt: Option<[u8; 32]> = if let Some(full_summary) =
        full_history.contexts.get(&context)
    {
        if let Some(salt) = full_summary.common_salts.first() {
            Some(*salt)
        } else if full_summary.voters.is_empty() {
            // Public context - no common salt needed
            None
        } else {
            // We're not the proposer - need to decrypt our invite manually
            // Get the proposer's public key
            let proposer_pubkey_bytes = full_history
                .voter_pubkeys
                .get(&HashableAccountId::from(full_summary.proposer.clone()))
                .ok_or("Proposer's public key not found")?;
            let proposer_pubkey = X25519PublicKey::from(*proposer_pubkey_bytes);

            // Query MongoDB to find the InviteVoter message for us
            let ss58_prefix = ss58_prefix_for_chain(chain_url);
            let my_ss58_address = format_account_ss58(&my_account_id, ss58_prefix);

            let mut client_options: ClientOptions = ClientOptions::parse(&config.mongodb_uri)
                .await
                .map_err(|e: mongodb::error::Error| e.to_string())?;
            client_options.app_name = Some("corevo-tui".to_string());
            let mongo_client = Client::with_options(client_options)
                .map_err(|e: mongodb::error::Error| e.to_string())?;

            let db = mongo_client.database(&config.mongodb_db);
            let coll = db.collection::<Document>("extrinsics");

            // Query for InviteVoter messages in this context
            let filter = doc! {
                "method": "remark",
                "args.remark": { "$regex": "^0xcc00ee", "$options": "i" },
            };

            let mut cursor = coll
                .find(filter)
                .await
                .map_err(|e: mongodb::error::Error| e.to_string())?;

            let mut encrypted_salt: Option<Vec<u8>> = None;

            while let Some(doc_result) = cursor
                .try_next()
                .await
                .map_err(|e: mongodb::error::Error| e.to_string())?
            {
                let remark = doc_result
                    .get_document("args")
                    .ok()
                    .and_then(|args: &Document| args.get("remark"))
                    .and_then(|v| match v {
                        Bson::String(s) => Some(s.as_str()),
                        _ => None,
                    });

                let Some(remark_hex) = remark else { continue };
                let Ok(remark_bytes) = corevo_lib::primitives::decode_hex(remark_hex) else {
                    continue;
                };
                let Ok(prefixed) = PrefixedCorevoRemark::decode(&mut remark_bytes.as_slice())
                else {
                    continue;
                };

                #[allow(irrefutable_let_patterns)]
                let CorevoRemark::V1(CorevoRemarkV1 {
                    context: msg_ctx,
                    msg,
                }) = prefixed.0
                else {
                    continue;
                };

                // Check if this is for our context
                if msg_ctx != context {
                    continue;
                }

                // Check if this is an InviteVoter message for us
                if let CorevoMessage::InviteVoter(voter_id, enc_salt) = msg {
                    // Check if this invite is for us (compare SS58 addresses)
                    let voter_ss58 = format_account_ss58(&voter_id, ss58_prefix);
                    if voter_ss58 == my_ss58_address {
                        encrypted_salt = Some(enc_salt);
                        break;
                    }
                }
            }

            let encrypted_salt =
                encrypted_salt.ok_or("No invite found for your account in this context")?;

            // Check if this is a public context (empty encrypted salt)
            if encrypted_salt.is_empty() {
                None
            } else {
                // Decrypt the common salt using our secret + proposer's public key
                let decrypted =
                    decrypt_from_sender(&account.x25519_secret, &proposer_pubkey, &encrypted_salt)
                        .map_err(|e| format!("Failed to decrypt common salt: {}", e))?;

                if decrypted.len() != 32 {
                    return Err("Decrypted salt has wrong length".to_string());
                }

                let mut salt = [0u8; 32];
                salt.copy_from_slice(&decrypted);
                Some(salt)
            }
        }
    } else {
        // Context not found in history - assume public context
        None
    };

    // Generate one-time salt for this vote
    let mut onetime_salt = [0u8; 32];
    thread_rng().fill_bytes(&mut onetime_salt);

    // Create the vote+salt structure
    let vote_and_salt = CorevoVoteAndSalt { vote, onetime_salt };

    // Generate commitment hash (with or without common salt)
    let commitment = vote_and_salt.commit(maybe_common_salt);

    // Encrypt vote+salt for self-recovery (using our own public key)
    let vote_and_salt_bytes = vote_and_salt.encode();
    let encrypted_vote_and_salt = encrypt_for_recipient(
        &account.x25519_secret,
        &account.x25519_public,
        &vote_and_salt_bytes,
    )
    .map_err(|e| format!("Failed to encrypt vote: {}", e))?;

    // Connect to chain
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    // Send the Commit message
    let commit_msg = CorevoMessage::Commit(commitment, encrypted_vote_and_salt);
    let commit_remark = PrefixedCorevoRemark::from(CorevoRemark::V1(CorevoRemarkV1 {
        context,
        msg: commit_msg,
    }));

    client
        .send_remark(&account.sr25519_keypair, commit_remark)
        .await
        .map_err(|e| format!("Failed to commit vote: {}", e))?;

    Ok(())
}

/// Async function to reveal a vote on the chain
async fn reveal_vote(
    chain_url: &str,
    secret_uri: &str,
    context: Option<corevo_lib::CorevoContext>,
    config: &corevo_lib::Config,
) -> Result<(), String> {
    use codec::Decode;
    use corevo_lib::{
        ChainClient, CorevoMessage, CorevoRemark, CorevoRemarkV1, CorevoVoteAndSalt,
        PrefixedCorevoRemark, decrypt_from_sender, derive_account_from_uri, format_account_ss58,
        ss58_prefix_for_chain,
    };
    use futures::TryStreamExt;
    use mongodb::{
        Client,
        bson::{Bson, Document, doc},
        options::ClientOptions,
    };

    let context = context.ok_or("No voting context selected")?;

    // Derive account for signing and decryption
    let account = derive_account_from_uri(secret_uri).map_err(|e| e.to_string())?;
    let my_account_id = account.sr25519_keypair.public_key().to_account_id();

    // Convert to SS58 format (that's how it's stored in MongoDB)
    let ss58_prefix = ss58_prefix_for_chain(chain_url);
    let my_ss58_address = format_account_ss58(&my_account_id, ss58_prefix);

    // We need to get the encrypted_vote_and_salt from our own Commit message
    // This requires querying MongoDB directly for our commit
    let mut client_options: ClientOptions = ClientOptions::parse(&config.mongodb_uri)
        .await
        .map_err(|e: mongodb::error::Error| e.to_string())?;
    client_options.app_name = Some("corevo-tui".to_string());
    let mongo_client =
        Client::with_options(client_options).map_err(|e: mongodb::error::Error| e.to_string())?;

    let db = mongo_client.database(&config.mongodb_db);
    let coll = db.collection::<Document>("extrinsics");

    // Query for our commit in this context (using SS58 address format)
    let filter = doc! {
        "method": "remark",
        "args.remark": { "$regex": "^0xcc00ee", "$options": "i" },
        "signer.Id": &my_ss58_address,
    };

    let mut cursor = coll
        .find(filter)
        .await
        .map_err(|e: mongodb::error::Error| e.to_string())?;

    let mut encrypted_vote_and_salt: Option<Vec<u8>> = None;

    // Find our Commit message for this context
    while let Some(doc) = cursor
        .try_next()
        .await
        .map_err(|e: mongodb::error::Error| e.to_string())?
    {
        let remark = doc
            .get_document("args")
            .ok()
            .and_then(|args: &Document| args.get("remark"))
            .and_then(|v| match v {
                Bson::String(s) => Some(s.as_str()),
                _ => None,
            });

        let Some(remark_hex) = remark else { continue };
        let Ok(remark_bytes) = corevo_lib::primitives::decode_hex(remark_hex) else {
            continue;
        };
        let Ok(prefixed) = PrefixedCorevoRemark::decode(&mut remark_bytes.as_slice()) else {
            continue;
        };

        #[allow(irrefutable_let_patterns)]
        let CorevoRemark::V1(CorevoRemarkV1 {
            context: msg_ctx,
            msg,
        }) = prefixed.0
        else {
            continue;
        };

        // Check if this is for our context
        if msg_ctx != context {
            continue;
        }

        // Check if this is a Commit message
        if let CorevoMessage::Commit(_commitment, encrypted) = msg {
            encrypted_vote_and_salt = Some(encrypted);
            break;
        }
    }

    let encrypted_vote_and_salt =
        encrypted_vote_and_salt.ok_or("Your commit message was not found on chain")?;

    // Decrypt the vote+salt using our own key
    let decrypted = decrypt_from_sender(
        &account.x25519_secret,
        &account.x25519_public,
        &encrypted_vote_and_salt,
    )
    .map_err(|e| format!("Failed to decrypt vote: {}", e))?;

    // Decode the vote+salt
    let vote_and_salt = CorevoVoteAndSalt::decode(&mut decrypted.as_slice())
        .map_err(|e| format!("Failed to decode vote: {}", e))?;

    // Connect to chain
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    // Send the RevealOneTimeSalt message
    let reveal_msg = CorevoMessage::RevealOneTimeSalt(vote_and_salt.onetime_salt);
    let reveal_remark = PrefixedCorevoRemark::from(CorevoRemark::V1(CorevoRemarkV1 {
        context,
        msg: reveal_msg,
    }));

    client
        .send_remark(&account.sr25519_keypair, reveal_remark)
        .await
        .map_err(|e| format!("Failed to reveal vote: {}", e))?;

    Ok(())
}

/// Async function to announce X25519 public key on chain
async fn announce_pubkey(chain_url: &str, secret_uri: &str) -> Result<(), String> {
    use corevo_lib::{
        ChainClient, CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1,
        PrefixedCorevoRemark, derive_account_from_uri,
    };

    // Derive account for signing
    let account = derive_account_from_uri(secret_uri).map_err(|e| e.to_string())?;

    // Connect to chain
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    // Create the announce message with empty string context (global announcement)
    let pubkey_bytes: [u8; 32] = account.x25519_public.to_bytes();
    let announce_msg = CorevoMessage::AnnounceOwnPubKey(pubkey_bytes);
    let announce_remark = PrefixedCorevoRemark::from(CorevoRemark::V1(CorevoRemarkV1 {
        context: CorevoContext::String(String::new()),
        msg: announce_msg,
    }));

    client
        .send_remark(&account.sr25519_keypair, announce_remark)
        .await
        .map_err(|e| format!("Failed to announce pubkey: {}", e))?;

    Ok(())
}
