use std::time::Instant;

use corevo_lib::{Config, CorevoContext, VotingHistory, derive_address_from_uri, ss58_prefix_for_chain, format_balance, token_info_for_chain, PublicKeyForEncryption, HashableAccountId};
use tokio::sync::mpsc;

use crate::action::Action;

/// Current screen/view
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Home,
    History,
    Voting,
    Config,
    Propose,
}

/// Loading state for async operations
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum LoadingState {
    #[default]
    Idle,
    Loading,
    Loaded,
    Error(String),
}

/// Application state
pub struct App {
    /// Current screen
    pub screen: Screen,

    /// Whether the app should quit
    pub should_quit: bool,

    /// Configuration
    pub config: Config,

    /// Config form state (editable fields)
    pub config_form: ConfigForm,

    /// Secret URI for signing (not persisted in config file)
    pub secret_uri: String,

    /// Derived SS58 address from secret_uri (with chain-appropriate prefix)
    pub derived_address: Option<String>,

    /// Account balance in native tokens (raw, without decimals applied)
    pub balance: Option<u128>,

    /// Balance loading state
    pub balance_loading: LoadingState,

    /// Voting history (loaded from indexer)
    pub history: Option<VotingHistory>,

    /// Loading state for history
    pub history_loading: LoadingState,

    /// Currently selected context in history view
    pub selected_context: Option<CorevoContext>,

    /// Selected index in lists
    pub selected_index: usize,

    /// Propose form state (new voting context)
    pub propose_form: ProposeForm,

    /// Loading state for propose submission
    pub propose_loading: LoadingState,

    /// Loading state for available voters
    pub voters_loading: LoadingState,

    /// Error message to display
    pub error_message: Option<String>,

    /// Action sender for async operations
    pub action_tx: mpsc::UnboundedSender<Action>,

    /// Last click time and position for double-click detection
    pub last_click: Option<(Instant, u16, u16)>,
}

/// Editable config form fields
#[derive(Debug, Clone, Default)]
pub struct ConfigForm {
    pub chain_url: String,
    pub mongodb_uri: String,
    pub mongodb_db: String,
    pub focused_field: usize,
}

/// An available voter with X25519 pubkey
#[derive(Debug, Clone)]
pub struct AvailableVoter {
    pub account_id: HashableAccountId,
    pub pubkey: PublicKeyForEncryption,
    pub selected: bool,
}

/// Which field is focused in the propose form
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProposeField {
    #[default]
    ContextName,
    Voter(usize),
    CreateButton,
}

/// Form state for creating new voting context
#[derive(Debug, Clone, Default)]
pub struct ProposeForm {
    pub context_name: String,
    /// Available voters (accounts with announced X25519 pubkeys)
    pub available_voters: Vec<AvailableVoter>,
    /// Currently focused field
    pub focused_field: ProposeField,
}

impl App {
    pub fn new(action_tx: mpsc::UnboundedSender<Action>) -> Self {
        let config = Config::default();
        let config_form = ConfigForm {
            chain_url: config.chain_url.clone(),
            mongodb_uri: config.mongodb_uri.clone(),
            mongodb_db: config.mongodb_db.clone(),
            focused_field: 0,
        };

        Self {
            screen: Screen::Home,
            should_quit: false,
            config,
            config_form,
            secret_uri: String::new(),
            derived_address: None,
            balance: None,
            balance_loading: LoadingState::Idle,
            history: None,
            history_loading: LoadingState::Idle,
            selected_context: None,
            selected_index: 0,
            propose_form: ProposeForm::default(),
            propose_loading: LoadingState::Idle,
            voters_loading: LoadingState::Idle,
            error_message: None,
            action_tx,
            last_click: None,
        }
    }

    /// Try to derive the SS58 address from the current secret_uri
    fn update_derived_address(&mut self) {
        // Reset balance when address changes
        self.balance = None;
        self.balance_loading = LoadingState::Idle;

        if self.secret_uri.is_empty() {
            self.derived_address = None;
        } else {
            let prefix = ss58_prefix_for_chain(&self.config_form.chain_url);
            match derive_address_from_uri(&self.secret_uri, prefix) {
                Ok(addr) => {
                    self.derived_address = Some(addr);
                    // Trigger balance load
                    let _ = self.action_tx.send(Action::LoadBalance);
                }
                Err(_) => self.derived_address = None,
            }
        }
    }

    /// Get formatted balance string with token symbol
    pub fn formatted_balance(&self) -> Option<String> {
        self.balance.map(|bal| {
            let info = token_info_for_chain(&self.config_form.chain_url);
            format!("{} {}", format_balance(bal, info.decimals), info.symbol)
        })
    }

    /// Handle an action and update state
    pub fn handle_action(&mut self, action: Action) {
        match action {
            // Navigation
            Action::NavigateHome => {
                self.screen = Screen::Home;
                self.selected_index = 0;
            }
            Action::NavigateHistory => {
                self.screen = Screen::History;
                self.selected_index = 0;
                // Auto-load history when navigating
                if self.history.is_none() && self.history_loading == LoadingState::Idle {
                    let _ = self.action_tx.send(Action::LoadHistory);
                }
            }
            Action::NavigateVoting => {
                self.screen = Screen::Voting;
            }
            Action::NavigateConfig => {
                self.screen = Screen::Config;
                self.config_form.focused_field = 0;
            }
            Action::NavigatePropose => {
                self.screen = Screen::Propose;
                self.propose_loading = LoadingState::Idle;
                self.propose_form.focused_field = ProposeField::ContextName;
                // Auto-load available voters if not already loaded
                if self.propose_form.available_voters.is_empty() && self.voters_loading == LoadingState::Idle {
                    let _ = self.action_tx.send(Action::LoadVoters);
                }
            }

            // List selection
            Action::SelectPrev => {
                let max = self.get_list_length();
                if max > 0 && self.selected_index > 0 {
                    self.selected_index -= 1;
                }
            }
            Action::SelectNext => {
                let max = self.get_list_length();
                if max > 0 && self.selected_index < max - 1 {
                    self.selected_index += 1;
                }
            }
            Action::SelectIndex(idx) => {
                let max = self.get_list_length();
                if idx < max {
                    self.selected_index = idx;
                    // Also update config focused field when on config screen
                    if self.screen == Screen::Config {
                        self.config_form.focused_field = idx;
                    }
                }
            }
            Action::ScrollUp(lines) => {
                if self.selected_index >= lines {
                    self.selected_index -= lines;
                } else {
                    self.selected_index = 0;
                }
            }
            Action::ScrollDown(lines) => {
                let max = self.get_list_length();
                if max > 0 {
                    self.selected_index = (self.selected_index + lines).min(max - 1);
                }
            }

            // Lifecycle
            Action::Quit => {
                self.should_quit = true;
            }
            Action::Tick => {
                // Periodic update logic if needed
            }
            Action::Render => {
                // Render is handled in main loop
            }

            // History
            Action::LoadHistory => {
                self.history_loading = LoadingState::Loading;
            }
            Action::HistoryLoaded(result) => match result {
                Ok(history) => {
                    self.history = Some(history);
                    self.history_loading = LoadingState::Loaded;
                }
                Err(e) => {
                    self.history_loading = LoadingState::Error(e);
                }
            },
            Action::SelectContext(ctx) => {
                self.selected_context = ctx;
            }

            // Balance
            Action::LoadBalance => {
                self.balance_loading = LoadingState::Loading;
            }
            Action::BalanceLoaded(result) => match result {
                Ok(balance) => {
                    self.balance = Some(balance);
                    self.balance_loading = LoadingState::Loaded;
                }
                Err(e) => {
                    self.balance = None;
                    self.balance_loading = LoadingState::Error(e);
                }
            },

            // Config
            Action::UpdateChainUrl(url) => {
                self.config_form.chain_url = url;
            }
            Action::UpdateMongoUri(uri) => {
                self.config_form.mongodb_uri = uri;
            }
            Action::UpdateMongoDb(db) => {
                self.config_form.mongodb_db = db;
            }
            Action::UpdateSecretUri(uri) => {
                self.secret_uri = uri;
            }
            Action::SaveConfig => {
                self.config.chain_url = self.config_form.chain_url.clone();
                self.config.mongodb_uri = self.config_form.mongodb_uri.clone();
                self.config.mongodb_db = self.config_form.mongodb_db.clone();
            }
            Action::ConfigSaved(result) => {
                if let Err(e) = result {
                    self.error_message = Some(e);
                }
            }
            Action::NextConfigField => {
                self.config_form.focused_field = (self.config_form.focused_field + 1) % 4;
            }
            Action::PrevConfigField => {
                if self.config_form.focused_field == 0 {
                    self.config_form.focused_field = 3;
                } else {
                    self.config_form.focused_field -= 1;
                }
            }

            // Propose context actions
            Action::ProposeContext => {
                self.propose_loading = LoadingState::Loading;
            }
            Action::ProposeSubmitted(result) => match result {
                Ok(()) => {
                    self.propose_loading = LoadingState::Loaded;
                }
                Err(e) => {
                    self.propose_loading = LoadingState::Error(e);
                }
            },

            // Voter loading actions
            Action::LoadVoters => {
                self.voters_loading = LoadingState::Loading;
            }
            Action::VotersLoaded(result) => match result {
                Ok(voters) => {
                    self.propose_form.available_voters = voters;
                    self.voters_loading = LoadingState::Loaded;
                }
                Err(e) => {
                    self.voters_loading = LoadingState::Error(e);
                }
            },
            Action::ToggleVoter(idx) => {
                if let Some(voter) = self.propose_form.available_voters.get_mut(idx) {
                    voter.selected = !voter.selected;
                }
            }
            Action::SelectAllVoters => {
                // If all are selected, deselect all; otherwise select all
                let all_selected = self.propose_form.available_voters.iter().all(|v| v.selected);
                for voter in &mut self.propose_form.available_voters {
                    voter.selected = !all_selected;
                }
            }
            Action::NextProposeField => {
                let num_voters = self.propose_form.available_voters.len();
                self.propose_form.focused_field = match self.propose_form.focused_field {
                    ProposeField::ContextName => {
                        if num_voters > 0 {
                            ProposeField::Voter(0)
                        } else {
                            ProposeField::CreateButton
                        }
                    }
                    ProposeField::Voter(i) => {
                        if i + 1 < num_voters {
                            ProposeField::Voter(i + 1)
                        } else {
                            ProposeField::CreateButton
                        }
                    }
                    ProposeField::CreateButton => ProposeField::ContextName,
                };
            }
            Action::PrevProposeField => {
                let num_voters = self.propose_form.available_voters.len();
                self.propose_form.focused_field = match self.propose_form.focused_field {
                    ProposeField::ContextName => ProposeField::CreateButton,
                    ProposeField::Voter(0) => ProposeField::ContextName,
                    ProposeField::Voter(i) => ProposeField::Voter(i - 1),
                    ProposeField::CreateButton => {
                        if num_voters > 0 {
                            ProposeField::Voter(num_voters - 1)
                        } else {
                            ProposeField::ContextName
                        }
                    }
                };
            }

            // Text input for config fields and propose form
            Action::InputChar(c) => {
                match self.screen {
                    Screen::Config => {
                        let field = self.config_form.focused_field;
                        match field {
                            0 => self.config_form.chain_url.push(c),
                            1 => self.config_form.mongodb_uri.push(c),
                            2 => self.config_form.mongodb_db.push(c),
                            3 => self.secret_uri.push(c),
                            _ => {}
                        }
                        // Update derived address when secret_uri or chain_url changes
                        if field == 0 || field == 3 {
                            self.update_derived_address();
                        }
                    }
                    Screen::Propose => {
                        if matches!(self.propose_form.focused_field, ProposeField::ContextName) {
                            self.propose_form.context_name.push(c);
                        }
                    }
                    _ => {}
                }
            }
            Action::InputBackspace => {
                match self.screen {
                    Screen::Config => {
                        let field = self.config_form.focused_field;
                        match field {
                            0 => { self.config_form.chain_url.pop(); }
                            1 => { self.config_form.mongodb_uri.pop(); }
                            2 => { self.config_form.mongodb_db.pop(); }
                            3 => { self.secret_uri.pop(); }
                            _ => {}
                        }
                        if field == 0 || field == 3 {
                            self.update_derived_address();
                        }
                    }
                    Screen::Propose => {
                        if matches!(self.propose_form.focused_field, ProposeField::ContextName) {
                            self.propose_form.context_name.pop();
                        }
                    }
                    _ => {}
                }
            }
            Action::InputDelete => {
                // Same as backspace for now (could implement cursor position later)
                match self.screen {
                    Screen::Config => {
                        let field = self.config_form.focused_field;
                        match field {
                            0 => { self.config_form.chain_url.pop(); }
                            1 => { self.config_form.mongodb_uri.pop(); }
                            2 => { self.config_form.mongodb_db.pop(); }
                            3 => { self.secret_uri.pop(); }
                            _ => {}
                        }
                        if field == 0 || field == 3 {
                            self.update_derived_address();
                        }
                    }
                    Screen::Propose => {
                        if matches!(self.propose_form.focused_field, ProposeField::ContextName) {
                            self.propose_form.context_name.pop();
                        }
                    }
                    _ => {}
                }
            }
            Action::InputClear => {
                match self.screen {
                    Screen::Config => {
                        let field = self.config_form.focused_field;
                        match field {
                            0 => self.config_form.chain_url.clear(),
                            1 => self.config_form.mongodb_uri.clear(),
                            2 => self.config_form.mongodb_db.clear(),
                            3 => self.secret_uri.clear(),
                            _ => {}
                        }
                        if field == 0 || field == 3 {
                            self.update_derived_address();
                        }
                    }
                    Screen::Propose => {
                        if matches!(self.propose_form.focused_field, ProposeField::ContextName) {
                            self.propose_form.context_name.clear();
                        }
                    }
                    _ => {}
                }
            }
            Action::InputPaste(text) => {
                match self.screen {
                    Screen::Config => {
                        let field = self.config_form.focused_field;
                        match field {
                            0 => self.config_form.chain_url.push_str(&text),
                            1 => self.config_form.mongodb_uri.push_str(&text),
                            2 => self.config_form.mongodb_db.push_str(&text),
                            3 => self.secret_uri.push_str(&text),
                            _ => {}
                        }
                        if field == 0 || field == 3 {
                            self.update_derived_address();
                        }
                    }
                    Screen::Propose => {
                        if matches!(self.propose_form.focused_field, ProposeField::ContextName) {
                            self.propose_form.context_name.push_str(&text);
                        }
                    }
                    _ => {}
                }
            }

            // Voting
            Action::StartVoting(ctx) => {
                self.selected_context = Some(ctx);
                self.screen = Screen::Voting;
            }
            Action::CastVote(_vote) => {
                // Handle vote casting
            }
            Action::VoteCast(result) => {
                if let Err(e) = result {
                    self.error_message = Some(e);
                }
            }

            // Errors
            Action::Error(msg) => {
                self.error_message = Some(msg);
            }
            Action::ClearError => {
                self.error_message = None;
            }

            // Mouse
            Action::RecordClick(row, col) => {
                self.last_click = Some((Instant::now(), row, col));
            }
        }
    }

    /// Check if a click at the given position is a double-click
    pub fn is_double_click(&self, row: u16, col: u16) -> bool {
        if let Some((last_time, last_row, last_col)) = self.last_click {
            let elapsed = last_time.elapsed();
            // Double-click if within 400ms and same row (allow some column tolerance)
            elapsed.as_millis() < 400 && last_row == row && (last_col as i16 - col as i16).abs() < 5
        } else {
            false
        }
    }

    /// Get the length of the current list based on screen
    pub fn get_list_length(&self) -> usize {
        match self.screen {
            Screen::Home => 5, // Menu items (History, Voting, Propose, Config, Quit)
            Screen::History => self
                .history
                .as_ref()
                .map(|h| h.contexts.len())
                .unwrap_or(0),
            Screen::Voting => 3, // Aye, Nay, Abstain
            Screen::Config => 4, // Form fields
            Screen::Propose => 2 + self.propose_form.available_voters.len(), // Context name + voters + button
        }
    }

    /// Get list of contexts from history for display
    pub fn get_context_list(&self) -> Vec<&CorevoContext> {
        self.history
            .as_ref()
            .map(|h| h.contexts.keys().collect())
            .unwrap_or_default()
    }

    /// Get selected voters for proposal
    pub fn get_selected_voters(&self) -> Vec<&AvailableVoter> {
        self.propose_form
            .available_voters
            .iter()
            .filter(|v| v.selected)
            .collect()
    }
}
