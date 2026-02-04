use std::time::Instant;

use corevo_lib::{
    AccountId32, Config, CorevoContext, HashableAccountId, PublicKeyForEncryption, VoteStatus,
    VotingHistory, format_balance, ss58_prefix_for_chain, token_info_for_chain,
};
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

    /// Cached account ID derived from secret_uri (to avoid re-deriving on every render)
    pub current_account_id: Option<AccountId32>,

    /// Account balance in native tokens (raw, without decimals applied)
    pub balance: Option<u128>,

    /// Balance loading state
    pub balance_loading: LoadingState,

    /// Request ID for balance loading (to ignore stale responses)
    pub balance_request_id: u64,

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

    /// Loading state for vote commit/reveal operations
    pub voting_loading: LoadingState,

    /// Loading state for pubkey announcement
    pub announce_loading: LoadingState,

    /// Whether to show the reveal confirmation dialog
    pub show_reveal_confirm: bool,

    /// Error message to display
    pub error_message: Option<String>,

    /// Action sender for async operations
    pub action_tx: mpsc::UnboundedSender<Action>,

    /// Last click time and position for double-click detection
    pub last_click: Option<(Instant, u16, u16)>,

    /// Show "Copied!" feedback (with timestamp for auto-clear)
    pub copied_feedback: Option<Instant>,
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
    UseCommonSalt,
    Voter(usize),
    CreateButton,
}

/// Form state for creating new voting context
#[derive(Debug, Clone)]
pub struct ProposeForm {
    pub context_name: String,
    /// Available voters (accounts with announced X25519 pubkeys)
    pub available_voters: Vec<AvailableVoter>,
    /// Currently focused field
    pub focused_field: ProposeField,
    /// Whether to use a common salt (encrypted for each voter)
    /// When false, votes can be publicly revealed without the proposer's secret
    pub use_common_salt: bool,
}

impl Default for ProposeForm {
    fn default() -> Self {
        Self {
            context_name: String::new(),
            available_voters: Vec::new(),
            focused_field: ProposeField::default(),
            use_common_salt: true, // Enable by default to hide votes from public
        }
    }
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
            current_account_id: None,
            balance: None,
            balance_loading: LoadingState::Idle,
            balance_request_id: 0,
            history: None,
            history_loading: LoadingState::Idle,
            selected_context: None,
            selected_index: 0,
            propose_form: ProposeForm::default(),
            propose_loading: LoadingState::Idle,
            voters_loading: LoadingState::Idle,
            voting_loading: LoadingState::Idle,
            announce_loading: LoadingState::Idle,
            show_reveal_confirm: false,
            error_message: None,
            action_tx,
            last_click: None,
            copied_feedback: None,
        }
    }

    /// Try to derive the SS58 address and account ID from the current secret_uri
    fn update_derived_address(&mut self) {
        // Check if this is actually a different account
        let old_account_id = self.current_account_id.clone();

        // Reset balance when address changes
        self.balance = None;
        self.balance_loading = LoadingState::Idle;

        if self.secret_uri.is_empty() {
            self.derived_address = None;
            self.current_account_id = None;
        } else {
            let prefix = ss58_prefix_for_chain(&self.config_form.chain_url);
            match corevo_lib::derive_account_from_uri(&self.secret_uri) {
                Ok(account) => {
                    let account_id = account.sr25519_keypair.public_key().to_account_id();
                    self.derived_address =
                        Some(corevo_lib::format_account_ss58(&account_id, prefix));
                    self.current_account_id = Some(account_id);
                    // Trigger balance load
                    let _ = self.action_tx.send(Action::LoadBalance);
                }
                Err(_) => {
                    self.derived_address = None;
                    self.current_account_id = None;
                }
            }
        }

        // If account changed, reset account-specific state
        if old_account_id != self.current_account_id {
            self.reset_account_state();
        }
    }

    /// Reset all account-specific state (history, votes, etc.)
    /// Called when switching accounts
    fn reset_account_state(&mut self) {
        // Preserve voter pubkey announcements by extracting them
        let voter_pubkeys = self.history.as_ref().map(|h| h.voter_pubkeys.clone());

        // Clear history and reload to get fresh data for new account
        self.history = None;
        self.history_loading = LoadingState::Idle;

        // If we have pubkeys, create a minimal history with just pubkeys
        // (actual vote history will be reloaded when user visits History/Vote screens)
        if let Some(pubkeys) = voter_pubkeys {
            use std::collections::HashMap;
            self.history = Some(corevo_lib::VotingHistory {
                contexts: HashMap::new(),
                voter_pubkeys: pubkeys,
            });
        }

        // Clear voting state
        self.selected_context = None;
        self.voting_loading = LoadingState::Idle;
        self.show_reveal_confirm = false;

        // Clear announce state
        self.announce_loading = LoadingState::Idle;

        // Reset selection
        self.selected_index = 0;
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
                self.show_reveal_confirm = false;
                self.voting_loading = LoadingState::Idle;
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
                self.selected_index = 0;
                // Auto-load history when navigating to voting if not already loaded
                if self.history.is_none()
                    && self.history_loading == LoadingState::Idle
                    && !self.secret_uri.is_empty()
                {
                    let _ = self.action_tx.send(Action::LoadHistory);
                }
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
                if self.propose_form.available_voters.is_empty()
                    && self.voters_loading == LoadingState::Idle
                {
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
                // Reserved for future periodic tasks
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
                self.selected_index = 0; // Reset selection when context changes
                self.show_reveal_confirm = false;
                self.voting_loading = LoadingState::Idle;
            }

            // Balance
            Action::LoadBalance => {
                self.balance_request_id = self.balance_request_id.wrapping_add(1);
                self.balance_loading = LoadingState::Loading;
            }
            Action::BalanceLoaded(request_id, result) => {
                // Ignore stale responses from old requests
                if request_id != self.balance_request_id {
                    return;
                }
                match result {
                    Ok(balance) => {
                        self.balance = Some(balance);
                        self.balance_loading = LoadingState::Loaded;
                    }
                    Err(e) => {
                        self.balance = None;
                        self.balance_loading = LoadingState::Error(e);
                    }
                }
            }

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

            // Announce pubkey
            Action::AnnouncePubkey => {
                self.announce_loading = LoadingState::Loading;
            }
            Action::AnnouncePubkeyResult(result) => {
                match result {
                    Ok(()) => {
                        self.announce_loading = LoadingState::Loaded;
                        // Reload history to see updated pubkey status
                        self.history_loading = LoadingState::Idle;
                        let _ = self.action_tx.send(Action::LoadHistory);
                    }
                    Err(e) => {
                        self.announce_loading = LoadingState::Error(e);
                    }
                }
            }
            Action::ClearAnnounceState => {
                self.announce_loading = LoadingState::Idle;
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
                let all_selected = self
                    .propose_form
                    .available_voters
                    .iter()
                    .all(|v| v.selected);
                for voter in &mut self.propose_form.available_voters {
                    voter.selected = !all_selected;
                }
            }
            Action::ToggleUseCommonSalt => {
                self.propose_form.use_common_salt = !self.propose_form.use_common_salt;
            }
            Action::NextProposeField => {
                let num_voters = self.propose_form.available_voters.len();
                self.propose_form.focused_field = match self.propose_form.focused_field {
                    ProposeField::ContextName => ProposeField::UseCommonSalt,
                    ProposeField::UseCommonSalt => {
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
                    ProposeField::UseCommonSalt => ProposeField::ContextName,
                    ProposeField::Voter(0) => ProposeField::UseCommonSalt,
                    ProposeField::Voter(i) => ProposeField::Voter(i - 1),
                    ProposeField::CreateButton => {
                        if num_voters > 0 {
                            ProposeField::Voter(num_voters - 1)
                        } else {
                            ProposeField::UseCommonSalt
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
            Action::InputBackspace => match self.screen {
                Screen::Config => {
                    let field = self.config_form.focused_field;
                    match field {
                        0 => {
                            self.config_form.chain_url.pop();
                        }
                        1 => {
                            self.config_form.mongodb_uri.pop();
                        }
                        2 => {
                            self.config_form.mongodb_db.pop();
                        }
                        3 => {
                            self.secret_uri.pop();
                        }
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
            },
            Action::InputDelete => {
                // Same as backspace for now (could implement cursor position later)
                match self.screen {
                    Screen::Config => {
                        let field = self.config_form.focused_field;
                        match field {
                            0 => {
                                self.config_form.chain_url.pop();
                            }
                            1 => {
                                self.config_form.mongodb_uri.pop();
                            }
                            2 => {
                                self.config_form.mongodb_db.pop();
                            }
                            3 => {
                                self.secret_uri.pop();
                            }
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
            Action::InputClear => match self.screen {
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
            },
            Action::InputPaste(text) => match self.screen {
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
            },

            // Voting
            Action::StartVoting(ctx) => {
                self.selected_context = Some(ctx);
                self.screen = Screen::Voting;
            }
            Action::CastVote(_vote) => {
                // Legacy - not used directly anymore
            }
            Action::CommitVote(_vote) => {
                self.voting_loading = LoadingState::Loading;
            }
            Action::CommitVoteResult(result) => match result {
                Ok(()) => {
                    self.voting_loading = LoadingState::Loaded;
                    // Clear selected context to go back to pending contexts list
                    self.selected_context = None;
                    self.selected_index = 0;
                    // Mark history as needing refresh (user can press 'r')
                    self.history_loading = LoadingState::Idle;
                }
                Err(e) => {
                    self.voting_loading = LoadingState::Error(e);
                }
            },
            Action::ShowRevealConfirm => {
                self.show_reveal_confirm = true;
            }
            Action::CancelReveal => {
                self.show_reveal_confirm = false;
            }
            Action::ConfirmReveal => {
                self.show_reveal_confirm = false;
                self.voting_loading = LoadingState::Loading;
            }
            Action::RevealVoteResult(result) => match result {
                Ok(()) => {
                    self.voting_loading = LoadingState::Loaded;
                    // Clear selected context to go back to pending contexts list
                    self.selected_context = None;
                    self.selected_index = 0;
                    // Mark history as needing refresh (user can press 'r')
                    self.history_loading = LoadingState::Idle;
                }
                Err(e) => {
                    self.voting_loading = LoadingState::Error(e);
                }
            },
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

            // Clipboard
            Action::CopyAddress(address) => {
                // Try external clipboard tools first (more reliable on Linux)
                let copied = Self::copy_to_clipboard_external(&address)
                    .or_else(|| Self::copy_to_clipboard_arboard(&address))
                    .unwrap_or(false);

                if copied {
                    self.copied_feedback = Some(Instant::now());
                }
            }
            Action::CopiedFeedback => {
                self.copied_feedback = Some(Instant::now());
            }
            Action::ClearCopiedFeedback => {
                self.copied_feedback = None;
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
            Screen::Home => 6, // Menu items (History, Voting, Propose, Config, Announce, Quit)
            Screen::History => self.history.as_ref().map(|h| h.contexts.len()).unwrap_or(0),
            Screen::Voting => {
                if self.selected_context.is_some() {
                    3 // Aye, Nay, Abstain
                } else {
                    // Number of pending vote contexts
                    self.get_pending_vote_contexts().len()
                }
            }
            Screen::Config => 4, // Form fields
            Screen::Propose => 2 + self.propose_form.available_voters.len(), // Context name + voters + button
        }
    }

    /// Get list of contexts from history for display
    #[allow(dead_code)]
    pub fn get_context_list(&self) -> Vec<&CorevoContext> {
        self.history
            .as_ref()
            .map(|h| h.contexts.keys().collect())
            .unwrap_or_default()
    }

    /// Get selected voters for proposal
    #[allow(dead_code)]
    pub fn get_selected_voters(&self) -> Vec<&AvailableVoter> {
        self.propose_form
            .available_voters
            .iter()
            .filter(|v| v.selected)
            .collect()
    }

    /// Get the current user's AccountId32 (cached, not re-derived on each call)
    pub fn get_current_account_id(&self) -> Option<&AccountId32> {
        self.current_account_id.as_ref()
    }

    /// Get contexts where the current user has pending action (need to commit or reveal)
    pub fn get_pending_vote_contexts(&self) -> Vec<&CorevoContext> {
        let Some(account_id) = self.get_current_account_id() else {
            return vec![];
        };
        let hashable_account_id = HashableAccountId::from(account_id.clone());

        let Some(history) = &self.history else {
            return vec![];
        };

        history
            .contexts
            .iter()
            .filter_map(|(ctx, summary)| {
                // Check if user is invited (in voters set)
                if !summary.voters.contains(&hashable_account_id) {
                    return None;
                }

                // Include contexts where user still has action to take
                match summary.votes.get(&hashable_account_id) {
                    None => Some(ctx),                                   // Need to commit
                    Some(VoteStatus::Committed(_)) => Some(ctx),         // Need to reveal
                    Some(VoteStatus::Revealed(_)) => None,               // Already revealed - done
                    Some(VoteStatus::RevealedWithoutCommitment) => None, // Invalid state
                }
            })
            .collect()
    }

    /// Get the current user's vote status for the selected context
    pub fn get_current_vote_status(&self) -> Option<&VoteStatus> {
        let account_id = self.get_current_account_id()?.clone();
        let hashable_account_id = HashableAccountId::from(account_id);
        let ctx = self.selected_context.as_ref()?;
        let history = self.history.as_ref()?;
        let summary = history.contexts.get(ctx)?;
        summary.votes.get(&hashable_account_id)
    }

    /// Get the context summary for the selected context
    #[allow(dead_code)]
    pub fn get_selected_context_summary(&self) -> Option<&corevo_lib::ContextSummary> {
        let ctx = self.selected_context.as_ref()?;
        let history = self.history.as_ref()?;
        history.contexts.get(ctx)
    }

    /// Check if the current user has announced their X25519 public key
    pub fn has_announced_pubkey(&self) -> Option<bool> {
        let account_id = self.get_current_account_id()?;
        let history = self.history.as_ref()?;
        let hashable = HashableAccountId::from(account_id.clone());
        Some(history.voter_pubkeys.contains_key(&hashable))
    }

    /// Get the current user's announced X25519 public key if available
    #[allow(dead_code)]
    pub fn get_announced_pubkey(&self) -> Option<&corevo_lib::PublicKeyForEncryption> {
        let account_id = self.get_current_account_id()?;
        let history = self.history.as_ref()?;
        let hashable = HashableAccountId::from(account_id.clone());
        history.voter_pubkeys.get(&hashable)
    }

    /// Check if the account is usable on chain (has balance > 0)
    /// Returns None if status is unknown (still loading), Some(true) if usable, Some(false) if not
    pub fn is_account_on_chain(&self) -> Option<bool> {
        if self.derived_address.is_none() {
            return Some(false); // No account configured
        }

        match &self.balance_loading {
            LoadingState::Idle => None,    // Not yet checked
            LoadingState::Loading => None, // Still loading
            LoadingState::Loaded => {
                // Account exists if balance > 0
                Some(self.balance.map(|b| b > 0).unwrap_or(false))
            }
            LoadingState::Error(_) => Some(false), // Error fetching = probably doesn't exist
        }
    }

    /// Check if copied feedback should still be shown (within 2 seconds)
    pub fn should_show_copied(&self) -> bool {
        self.copied_feedback
            .map(|t| t.elapsed().as_secs() < 2)
            .unwrap_or(false)
    }

    /// Check if the selected context is a public proposal (no common salt)
    pub fn is_public_proposal(&self) -> bool {
        let Some(ctx) = self.selected_context.as_ref() else {
            return false;
        };
        let Some(history) = self.history.as_ref() else {
            return false;
        };
        let Some(summary) = history.contexts.get(ctx) else {
            return false;
        };
        summary.common_salts.is_empty()
    }

    /// Check if a home menu item is disabled
    /// Items: 0=History, 1=Vote, 2=Propose, 3=Config, 4=Announce, 5=Quit
    pub fn is_home_menu_item_disabled(&self, index: usize) -> bool {
        let can_use_chain = self.is_account_on_chain() == Some(true);
        let can_announce = can_use_chain && self.has_announced_pubkey() == Some(false);

        match index {
            0 => false,                                            // History - always enabled
            1 => !can_use_chain && self.derived_address.is_some(), // Vote
            2 => !can_use_chain && self.derived_address.is_some(), // Propose
            3 => false,                                            // Config - always enabled
            4 => !can_announce,                                    // Announce
            5 => false,                                            // Quit - always enabled
            _ => false,
        }
    }

    /// Find next enabled home menu item (wrapping)
    pub fn next_enabled_home_item(&self, current: usize) -> usize {
        let total = 6;
        for offset in 1..=total {
            let next = (current + offset) % total;
            if !self.is_home_menu_item_disabled(next) {
                return next;
            }
        }
        current // All disabled, stay put
    }

    /// Find previous enabled home menu item (wrapping)
    pub fn prev_enabled_home_item(&self, current: usize) -> usize {
        let total = 6;
        for offset in 1..=total {
            let prev = (current + total - offset) % total;
            if !self.is_home_menu_item_disabled(prev) {
                return prev;
            }
        }
        current // All disabled, stay put
    }

    /// Try to copy text using external clipboard tools (xclip, xsel, wl-copy)
    fn copy_to_clipboard_external(text: &str) -> Option<bool> {
        use std::io::Write;
        use std::process::{Command, Stdio};

        // Try wl-copy first (Wayland)
        if let Ok(mut child) = Command::new("wl-copy")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            && let Some(mut stdin) = child.stdin.take()
            && stdin.write_all(text.as_bytes()).is_ok()
        {
            drop(stdin);
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                return Some(true);
            }
        }

        // Try xclip (X11)
        if let Ok(mut child) = Command::new("xclip")
            .args(["-selection", "clipboard"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            && let Some(mut stdin) = child.stdin.take()
            && stdin.write_all(text.as_bytes()).is_ok()
        {
            drop(stdin);
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                return Some(true);
            }
        }

        // Try xsel (X11 alternative)
        if let Ok(mut child) = Command::new("xsel")
            .args(["--clipboard", "--input"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            && let Some(mut stdin) = child.stdin.take()
            && stdin.write_all(text.as_bytes()).is_ok()
        {
            drop(stdin);
            if child.wait().map(|s| s.success()).unwrap_or(false) {
                return Some(true);
            }
        }

        None // No external tool worked
    }

    /// Fallback: try arboard (may not work well on Linux without persistence)
    fn copy_to_clipboard_arboard(text: &str) -> Option<bool> {
        // On Linux, spawn a thread to keep clipboard alive
        #[cfg(target_os = "linux")]
        {
            let text = text.to_string();
            std::thread::spawn(move || {
                if let Ok(mut clipboard) = arboard::Clipboard::new() {
                    let _ = clipboard.set_text(&text);
                    // Keep alive for paste operations
                    std::thread::sleep(std::time::Duration::from_secs(30));
                }
            });
            Some(true)
        }

        #[cfg(not(target_os = "linux"))]
        {
            if let Ok(mut clipboard) = arboard::Clipboard::new()
                && clipboard.set_text(text).is_ok()
            {
                return Some(true);
            }
            None
        }
    }
}
