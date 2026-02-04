use corevo_lib::{CorevoContext, VotingHistory};
use crate::app::AvailableVoter;

/// Actions that can be dispatched to update application state (Elm architecture)
#[derive(Debug, Clone)]
pub enum Action {
    // Navigation
    NavigateHome,
    NavigateHistory,
    NavigateVoting,
    NavigateConfig,
    NavigatePropose,

    // List selection
    SelectPrev,
    SelectNext,
    SelectIndex(usize),
    ScrollUp(usize),
    ScrollDown(usize),

    // Application lifecycle
    Quit,
    Tick,
    Render,

    // History actions
    LoadHistory,
    HistoryLoaded(Result<VotingHistory, String>),
    SelectContext(Option<CorevoContext>),

    // Balance actions
    LoadBalance,
    BalanceLoaded(Result<u128, String>),

    // Config actions
    SaveConfig,
    ConfigSaved(Result<(), String>),
    UpdateChainUrl(String),
    UpdateMongoUri(String),
    UpdateMongoDb(String),
    UpdateSecretUri(String),
    NextConfigField,
    PrevConfigField,

    // Text input (for config fields)
    InputChar(char),
    InputBackspace,
    InputDelete,
    InputClear,
    InputPaste(String),

    // Voting actions
    StartVoting(CorevoContext),
    CastVote(corevo_lib::CorevoVote),
    CommitVote(corevo_lib::CorevoVote),
    CommitVoteResult(Result<(), String>),
    ShowRevealConfirm,
    CancelReveal,
    ConfirmReveal,
    RevealVoteResult(Result<(), String>),
    VoteCast(Result<(), String>),

    // Announce pubkey
    AnnouncePubkey,
    AnnouncePubkeyResult(Result<(), String>),
    ClearAnnounceState,

    // Propose context actions
    ProposeContext,
    ProposeSubmitted(Result<(), String>),
    LoadVoters,
    VotersLoaded(Result<Vec<AvailableVoter>, String>),
    ToggleVoter(usize),
    SelectAllVoters,
    NextProposeField,
    PrevProposeField,

    // Error handling
    Error(String),
    ClearError,

    // Mouse
    RecordClick(u16, u16), // row, col

    // Clipboard
    CopyAddress(String),
    CopiedFeedback,
    ClearCopiedFeedback,
}
