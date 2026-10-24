//! What quitting would lose (SPEC 6, 7, 8): one coordinator for every quit path. A create in
//! flight is owned here, not by its window: Esc or closing after the request was sent hides the
//! view, and the late answer is presented to the user.

use crate::receive::Receipt;
use crate::sent::ServerCreated;
use crate::service::ApiError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blocker {
    /// Received secrets not destroyed or not saved (count).
    Received(usize),
    /// A create request is on its way: its link would be lost.
    Creating,
    /// Created on the server, not saved on this computer: the link exists only in memory.
    NotSavedLocally,
    /// Quick drop holds typed or pasted text.
    QuickDropInput,
}

pub struct QuitInputs<'a> {
    pub receipts: &'a [&'a Receipt],
    pub creates: &'a [&'a CreateOp],
    pub quick_drop_has_input: bool,
}

pub fn blockers(i: &QuitInputs) -> Vec<Blocker> {
    let mut v = Vec::new();
    let held = i.receipts.iter().filter(|r| r.blocks_quit()).count();
    if held > 0 {
        v.push(Blocker::Received(held));
    }
    if i.creates.iter().any(|c| c.phase() == CreatePhase::Sending) {
        v.push(Blocker::Creating);
    }
    if i.creates
        .iter()
        .any(|c| c.phase() == CreatePhase::NotSavedLocally)
    {
        v.push(Blocker::NotSavedLocally);
    }
    if i.quick_drop_has_input {
        v.push(Blocker::QuickDropInput);
    }
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatePhase {
    Editing,
    Sending,
    /// The service has it; some local step failed (Retry, Copy by hand).
    NotSavedLocally,
    /// Done: the history entry exists.
    Done,
    /// Refused (the form is kept).
    Failed,
    /// The connection broke: it may or may not exist on the service.
    Unknown,
}

/// One create from A1 or C.
pub struct CreateOp {
    phase: CreatePhase,
    /// Esc or the window closed after the request was sent: present the result elsewhere.
    detached: bool,
    created: Option<ServerCreated>,
    error: Option<ApiError>,
}

impl Default for CreateOp {
    fn default() -> Self {
        CreateOp::new()
    }
}

impl CreateOp {
    pub fn new() -> CreateOp {
        CreateOp {
            phase: CreatePhase::Editing,
            detached: false,
            created: None,
            error: None,
        }
    }

    pub fn phase(&self) -> CreatePhase {
        self.phase
    }

    pub fn detached(&self) -> bool {
        self.detached
    }

    pub fn error(&self) -> Option<&ApiError> {
        self.error.as_ref()
    }

    /// Create pressed: true once; a second press while sending sends nothing.
    pub fn start(&mut self) -> bool {
        if !matches!(self.phase, CreatePhase::Editing | CreatePhase::Failed) {
            return false;
        }
        self.phase = CreatePhase::Sending;
        self.error = None;
        true
    }

    /// The server answer. Ok moves to NotSavedLocally until `local_done`.
    pub fn answered(&mut self, r: Result<ServerCreated, ApiError>) {
        if self.phase != CreatePhase::Sending {
            return;
        }
        match r {
            Ok(sc) => {
                self.created = Some(sc);
                self.phase = CreatePhase::NotSavedLocally;
            }
            // The request may have created it (or did, unreadably): no silent second create.
            Err(e @ (ApiError::Network | ApiError::CreatedUnreadable)) => {
                self.phase = CreatePhase::Unknown;
                self.error = Some(e);
            }
            Err(e) => {
                self.phase = CreatePhase::Failed;
                self.error = Some(e);
            }
        }
    }

    pub fn created_mut(&mut self) -> Option<&mut ServerCreated> {
        self.created.as_mut()
    }

    pub fn created(&self) -> Option<&ServerCreated> {
        self.created.as_ref()
    }

    /// After an unknown outcome the user may create again, explicitly (a new secret).
    pub fn create_again(&mut self) -> bool {
        if self.phase != CreatePhase::Unknown {
            return false;
        }
        self.phase = CreatePhase::Editing;
        self.error = None;
        true
    }

    /// Every local step done (`Sent::finish` returned Ok).
    pub fn local_done(&mut self) {
        if self.created.as_ref().is_some_and(ServerCreated::complete) {
            self.phase = CreatePhase::Done;
        }
    }

    /// Esc / close. Before sending: true, drop everything. After: the op stays alive, detached.
    pub fn cancel(&mut self) -> bool {
        match self.phase {
            CreatePhase::Editing | CreatePhase::Failed => true,
            CreatePhase::Sending | CreatePhase::NotSavedLocally => {
                self.detached = true;
                false
            }
            CreatePhase::Done | CreatePhase::Unknown => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeApi, ORIGIN};
    use crate::receive::Receipt;
    use crate::sent::{Draft, create_on_server};
    use crate::service::SecretsApi;
    use crate::time::ManualClock;
    use sdrop::api::Origin;
    use sdrop::format::Content;
    use zeroize::Zeroizing;

    fn draft() -> Draft {
        Draft {
            text: Zeroizing::new("pw".into()),
            files: vec![],
            passphrase: None,
            ttl: 3600,
            label: String::new(),
            notify: true,
        }
    }

    #[test]
    fn create_once_and_esc_after_sending_keeps_the_op() {
        let mut api = FakeApi::new(ManualClock::at(0));
        let mut op = CreateOp::new();
        assert!(op.start());
        assert!(!op.start(), "a second press sends nothing");
        // Esc while the request is out: not dropped.
        assert!(!op.cancel());
        assert!(op.detached());
        let none: [&Receipt; 0] = [];
        let creates = [&op];
        let q = QuitInputs {
            receipts: &none,
            creates: &creates,
            quick_drop_has_input: false,
        };
        assert_eq!(blockers(&q), vec![Blocker::Creating]);
        // The late 201 is kept, to be presented.
        op.answered(create_on_server(&mut api, &draft(), 0));
        assert_eq!(op.phase(), CreatePhase::NotSavedLocally);
        assert!(op.created().unwrap().recipient.contains("/s/"));
        let creates = [&op];
        let q = QuitInputs {
            receipts: &none,
            creates: &creates,
            quick_drop_has_input: false,
        };
        assert_eq!(blockers(&q), vec![Blocker::NotSavedLocally]);
        assert_eq!(api.calls("create"), 1);
    }

    #[test]
    fn esc_before_sending_drops_and_errors_keep_the_form() {
        let mut op = CreateOp::new();
        assert!(op.cancel());
        let mut op = CreateOp::new();
        op.start();
        op.answered(Err(ApiError::TooManyRequests));
        assert_eq!(op.phase(), CreatePhase::Failed);
        assert!(op.start(), "the user may press Create again");
        op.answered(Err(ApiError::Network));
        assert_eq!(op.phase(), CreatePhase::Unknown);
        assert!(!op.start(), "unknown outcome: no silent second create");
        assert!(op.create_again());
        assert!(op.start());
        // 201 with an unreadable body: the secret exists, Create is not offered again by itself.
        op.answered(Err(ApiError::CreatedUnreadable));
        assert_eq!(op.phase(), CreatePhase::Unknown);
        assert!(!op.start());
        // A refusal before creating (5xx, 429) keeps the form for another try.
        let mut op = CreateOp::new();
        op.start();
        op.answered(Err(ApiError::Unexpected));
        assert_eq!(op.phase(), CreatePhase::Failed);
    }

    #[test]
    fn quit_blockers_from_receipts_and_quick_drop() {
        let mut api = FakeApi::new(ManualClock::at(0));
        let link = api
            .create(&Content::Text("s"), None, 3600)
            .unwrap()
            .recipient
            .to_string();
        let origin = Origin::parse(ORIGIN).unwrap();
        let idle = Receipt::open(&origin, &link).unwrap();
        let mut held = Receipt::open(&origin, &link).unwrap();
        let id = held.begin().unwrap();
        let none: [&CreateOp; 0] = [];
        let q = QuitInputs {
            receipts: &[&idle],
            creates: &none,
            quick_drop_has_input: false,
        };
        assert!(blockers(&q).is_empty());
        let res = api.consume(&id);
        held.consumed(res, None, 0);
        let q = QuitInputs {
            receipts: &[&idle, &held],
            creates: &none,
            quick_drop_has_input: true,
        };
        assert_eq!(
            blockers(&q),
            vec![Blocker::Received(1), Blocker::QuickDropInput]
        );
        held.destroy();
        let q = QuitInputs {
            receipts: &[&held],
            creates: &none,
            quick_drop_has_input: false,
        };
        assert!(blockers(&q).is_empty());
    }
}
