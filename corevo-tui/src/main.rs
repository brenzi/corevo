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
use components::{config::ConfigComponent, history::HistoryComponent, home::HomeComponent, propose::ProposeComponent, voting::VotingComponent};
use event::{Event, EventHandler};
use tui::Tui;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;
    env_logger::init();

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
        tui.draw(|frame| {
            match app.screen {
                Screen::Home => HomeComponent::render(&app, frame),
                Screen::History => HistoryComponent::render(&app, frame),
                Screen::Voting => VotingComponent::render(&app, frame),
                Screen::Config => ConfigComponent::render(&app, frame),
                Screen::Propose => ProposeComponent::render(&app, frame),
            }
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
                            let tx = action_tx.clone();
                            tokio::spawn(async move {
                                let result = load_balance(&chain_url, &secret_uri).await;
                                let _ = tx.send(Action::BalanceLoaded(result));
                            });
                        }
                    }
                    Action::ProposeContext => {
                        let chain_url = app.config_form.chain_url.clone();
                        let secret_uri = app.secret_uri.clone();
                        let context_name = app.propose_form.context_name.clone();
                        let selected_voters: Vec<_> = app.propose_form.available_voters
                            .iter()
                            .filter(|v| v.selected)
                            .map(|v| (v.account_id.clone(), v.pubkey))
                            .collect();
                        let tx = action_tx.clone();
                        tokio::spawn(async move {
                            let result = propose_context(&chain_url, &secret_uri, &context_name, &selected_voters).await;
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
        Event::Key(key) => handle_key_event(app, key).into_iter().collect(),
        Event::Mouse(mouse) => handle_mouse_event(app, mouse),
        Event::Resize(_, _) => vec![Action::Render],
    }
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
    match key.code {
        KeyCode::Char('q') => Some(Action::Quit),
        KeyCode::Char('1') => Some(Action::NavigateHistory),
        KeyCode::Char('2') => Some(Action::NavigateVoting),
        KeyCode::Char('3') => Some(Action::NavigatePropose),
        KeyCode::Char('4') => Some(Action::NavigateConfig),
        KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectPrev),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectNext),
        KeyCode::Enter => {
            match app.selected_index {
                0 => Some(Action::NavigateHistory),
                1 => Some(Action::NavigateVoting),
                2 => Some(Action::NavigatePropose),
                3 => Some(Action::NavigateConfig),
                4 => Some(Action::Quit),
                _ => None,
            }
        }
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

fn handle_voting_keys(_app: &App, key: KeyEvent) -> Option<Action> {
    match key.code {
        KeyCode::Esc => Some(Action::NavigateHome),
        KeyCode::Char('1') => Some(Action::CastVote(corevo_lib::CorevoVote::Aye)),
        KeyCode::Char('2') => Some(Action::CastVote(corevo_lib::CorevoVote::Nay)),
        KeyCode::Char('3') => Some(Action::CastVote(corevo_lib::CorevoVote::Abstain)),
        KeyCode::Up | KeyCode::Char('k') => Some(Action::SelectPrev),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::SelectNext),
        _ => None,
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
            if let Ok(mut clipboard) = arboard::Clipboard::new() {
                if let Ok(text) = clipboard.get_text() {
                    // Clean the text - remove newlines, trim whitespace
                    let clean_text = text.trim().replace('\n', "").replace('\r', "");
                    if !clean_text.is_empty() {
                        return Some(Action::InputPaste(clean_text));
                    }
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

    let selected_count = app.propose_form.available_voters.iter().filter(|v| v.selected).count();
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
            ProposeField::Voter(idx) => Some(Action::ToggleVoter(idx)),
            ProposeField::CreateButton if can_submit => Some(Action::ProposeContext),
            _ => None,
        },

        // Enter toggles voter or activates button
        KeyCode::Enter => match app.propose_form.focused_field {
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
            if matches!(app.propose_form.focused_field, ProposeField::ContextName) {
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    if let Ok(text) = clipboard.get_text() {
                        let clean_text = text.trim().replace('\n', "").replace('\r', "");
                        if !clean_text.is_empty() {
                            return Some(Action::InputPaste(clean_text));
                        }
                    }
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
        MouseEventKind::Down(MouseButton::Left) => {
            handle_mouse_click(app, mouse.row, mouse.column)
        }
        // Scroll wheel navigation works everywhere
        MouseEventKind::ScrollUp => vec![Action::SelectPrev],
        MouseEventKind::ScrollDown => vec![Action::SelectNext],
        _ => vec![],
    }
}

/// Handle mouse click based on screen and position
fn handle_mouse_click(app: &App, row: u16, col: u16) -> Vec<Action> {
    let is_double = app.is_double_click(row, col);
    let mut actions = vec![];

    match app.screen {
        Screen::Home => {
            // Home screen layout: margin(2), title(3), info(9), menu starts at row 2+3+9=14
            // Menu has border, so items start at row 15
            // Items: History(0), Voting(1), Propose(2), Config(3), Quit(4)
            let menu_start = 2 + 3 + 9 + 1; // margin + title + info + border
            let r = row as usize;
            if r >= menu_start && r < menu_start + 5 {
                let idx = r - menu_start;
                if is_double {
                    // Double-click: navigate directly
                    match idx {
                        0 => actions.push(Action::NavigateHistory),
                        1 => actions.push(Action::NavigateVoting),
                        2 => actions.push(Action::NavigatePropose),
                        3 => actions.push(Action::NavigateConfig),
                        4 => actions.push(Action::Quit),
                        _ => {}
                    }
                } else {
                    // Single click: just select
                    actions.push(Action::SelectIndex(idx));
                }
            }
        }
        Screen::History => {
            // History layout: margin(1), title(3), content area
            // Content area: list on left (40%) with border
            // List items start at row: 1 + 3 + 1 (margin + title + list border) = 5
            let list_start = 1 + 3 + 1;
            let r = row as usize;
            let max = app.get_list_length();
            if r >= list_start && max > 0 {
                let idx = r - list_start;
                if idx < max {
                    actions.push(Action::SelectIndex(idx));
                }
            }
        }
        Screen::Voting => {
            // Voting layout: margin(1), title(3), context(6), vote options
            // Vote options have border, items start at row: 1+3+6+1 = 11
            let options_start = 1 + 3 + 6 + 1;
            let r = row as usize;
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
            // Propose layout: margin(1), title(3), instructions(5), context field
            // Clicking anywhere in the form area is fine (only one field)
        }
    }

    // Always record the click for double-click detection
    actions.push(Action::RecordClick(row, col));
    actions
}

/// Async function to load history from indexer
async fn load_history(config: &corevo_lib::Config, secret_uri: Option<&str>) -> Result<corevo_lib::VotingHistory, String> {
    let mut query = corevo_lib::HistoryQuery::new(config);

    // If we have a secret URI, derive the account for decryption
    if let Some(uri) = secret_uri {
        if !uri.is_empty() {
            if let Ok(account) = corevo_lib::derive_account_from_uri(uri) {
                query = query.with_known_accounts(vec![account]);
            }
        }
    }

    query.execute()
        .await
        .map_err(|e| e.to_string())
}

/// Async function to load account balance from chain
async fn load_balance(chain_url: &str, secret_uri: &str) -> Result<u128, String> {
    use corevo_lib::{ChainClient, derive_account_from_uri};

    // Derive account to get the account ID
    let account = derive_account_from_uri(secret_uri)
        .map_err(|e| e.to_string())?;
    let account_id = account.sr25519_keypair.public_key().to_account_id();

    // Connect to chain and fetch balance
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    client.get_account_balance(&account_id)
        .await
        .map_err(|e| e.to_string())
}

/// Async function to load available voters (accounts with announced X25519 pubkeys)
async fn load_available_voters(config: &corevo_lib::Config) -> Result<Vec<crate::app::AvailableVoter>, String> {
    use corevo_lib::HistoryQuery;
    use crate::app::AvailableVoter;

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
    selected_voters: &[(corevo_lib::HashableAccountId, corevo_lib::PublicKeyForEncryption)],
) -> Result<(), String> {
    use corevo_lib::{
        ChainClient, derive_account_from_uri, encrypt_for_recipient,
        CorevoContext, CorevoMessage, CorevoRemark, CorevoRemarkV1, PrefixedCorevoRemark,
    };
    use rand::{RngCore, thread_rng};
    use x25519_dalek::PublicKey as X25519PublicKey;

    // Derive account for signing and encryption
    let account = derive_account_from_uri(secret_uri)
        .map_err(|e| e.to_string())?;

    // Create the context
    let context = CorevoContext::String(context_name.to_string());

    // Connect to chain
    let client = ChainClient::connect(chain_url)
        .await
        .map_err(|e| e.to_string())?;

    // Step 1: Announce proposer's X25519 public key in this context
    let pubkey_bytes: [u8; 32] = account.x25519_public.to_bytes();
    let announce_msg = CorevoMessage::AnnounceOwnPubKey(pubkey_bytes);
    let announce_remark = PrefixedCorevoRemark::from(CorevoRemark::V1(CorevoRemarkV1 {
        context: context.clone(),
        msg: announce_msg,
    }));

    client.send_remark(&account.sr25519_keypair, announce_remark)
        .await
        .map_err(|e| format!("Failed to announce pubkey: {}", e))?;

    // Step 2: Generate a common salt for this voting session
    let mut common_salt = [0u8; 32];
    thread_rng().fill_bytes(&mut common_salt);

    // Step 3: Invite each selected voter by sending encrypted common salt
    for (voter_account_id, voter_pubkey_bytes) in selected_voters {
        let voter_pubkey = X25519PublicKey::from(*voter_pubkey_bytes);

        // Encrypt the common salt for this voter
        let encrypted_salt = encrypt_for_recipient(&account.x25519_secret, &voter_pubkey, &common_salt)
            .map_err(|e| format!("Failed to encrypt for voter: {}", e))?;

        let invite_msg = CorevoMessage::InviteVoter(voter_account_id.0.clone(), encrypted_salt);
        let invite_remark = PrefixedCorevoRemark::from(CorevoRemark::V1(CorevoRemarkV1 {
            context: context.clone(),
            msg: invite_msg,
        }));

        client.send_remark(&account.sr25519_keypair, invite_remark)
            .await
            .map_err(|e| format!("Failed to invite voter: {}", e))?;
    }

    Ok(())
}
