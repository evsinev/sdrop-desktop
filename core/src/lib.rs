//! Logic of the Payneteasy Secrets desktop client without UI (SPEC 2): history index, OS vault,
//! clipboard service, status polling, operations and screen states. The GPUI layer (`app`) only
//! draws these states and forwards user actions.

pub mod clipboard;
pub mod clipthread;
pub mod engine;
#[cfg(any(test, feature = "test-loopback"))]
pub mod fake;
pub mod history;
pub mod quit;
pub mod receive;
pub mod save;
pub mod sent;
pub mod service;
pub mod time;
pub mod vault;

pub use sdrop;

/// The trusted service origin, as `sdrop` resolves it (SDROP_ORIGIN or the one built in).
pub fn origin() -> Result<sdrop::api::Origin, sdrop::api::CliError> {
    sdrop::api::Origin::configured()
}
