//! macOS parts of the probe: a Quit guard on GPUI's application delegate and notifications
//! through UNUserNotificationCenter with a click handler.

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use block2::RcBlock;
use objc2::rc::Retained;
use objc2::runtime::{AnyClass, AnyObject, Bool, Imp, NSObject, ProtocolObject, Sel};
use objc2::{AllocAnyThread, define_class, msg_send, sel};
use objc2_foundation::{NSBundle, NSError, NSObjectProtocol, NSString};
use objc2_user_notifications::{
    UNAuthorizationOptions, UNMutableNotificationContent, UNNotification,
    UNNotificationPresentationOptions, UNNotificationRequest, UNNotificationResponse,
    UNUserNotificationCenter, UNUserNotificationCenterDelegate,
};

/// While set, `applicationShouldTerminate:` cancels the quit and raises QUIT_ASKED.
pub static HOLD: AtomicBool = AtomicBool::new(false);
pub static QUIT_ASKED: AtomicBool = AtomicBool::new(false);
/// Identifier of the last clicked notification, taken by the UI loop.
pub static CLICKED: Mutex<Option<String>> = Mutex::new(None);

const NS_TERMINATE_CANCEL: usize = 0;
const NS_TERMINATE_NOW: usize = 1;

extern "C-unwind" fn should_terminate(_this: &AnyObject, _cmd: Sel, _app: *mut AnyObject) -> usize {
    if HOLD.load(Ordering::SeqCst) {
        QUIT_ASKED.store(true, Ordering::SeqCst);
        NS_TERMINATE_CANCEL
    } else {
        NS_TERMINATE_NOW
    }
}

/// Adds `applicationShouldTerminate:` to GPUI's delegate class at runtime (GPUI does not define
/// it, so AppKit asks no one and quits). True when the method was added.
pub fn install_terminate_guard() -> bool {
    let Some(cls) = AnyClass::get(c"GPUIApplicationDelegate") else {
        return false;
    };
    unsafe {
        let imp: Imp = std::mem::transmute::<
            extern "C-unwind" fn(&AnyObject, Sel, *mut AnyObject) -> usize,
            Imp,
        >(should_terminate);
        objc2::ffi::class_addMethod(
            cls as *const AnyClass as *mut AnyClass,
            sel!(applicationShouldTerminate:),
            imp,
            c"Q@:@".as_ptr(),
        )
        .as_bool()
    }
}

pub fn session_kind() -> &'static str {
    "macOS"
}

pub fn popup_kind() -> gpui_kit::WindowKind {
    gpui_kit::WindowKind::PopUp
}

/// NSPasteboard.changeCount: every write by anyone bumps it, so "still ours" needs no read.
pub fn clipboard_change_count() -> Option<i64> {
    Some(objc2_app_kit::NSPasteboard::generalPasteboard().changeCount() as i64)
}

/// UNUserNotificationCenter throws for a process without a bundle identifier.
pub fn bundle_id() -> Option<String> {
    NSBundle::mainBundle()
        .bundleIdentifier()
        .map(|s| s.to_string())
}

define_class!(
    #[unsafe(super(NSObject))]
    #[name = "PnesecretsProbeNotificationDelegate"]
    struct NotificationDelegate;

    unsafe impl NSObjectProtocol for NotificationDelegate {}

    unsafe impl UNUserNotificationCenterDelegate for NotificationDelegate {
        // Show banners while the app is in front too (macOS hides them by default).
        #[unsafe(method(userNotificationCenter:willPresentNotification:withCompletionHandler:))]
        fn will_present(
            &self,
            _center: &UNUserNotificationCenter,
            _notification: &UNNotification,
            handler: &block2::DynBlock<dyn Fn(UNNotificationPresentationOptions)>,
        ) {
            handler
                .call((UNNotificationPresentationOptions::Banner
                    | UNNotificationPresentationOptions::List,));
        }

        #[unsafe(method(userNotificationCenter:didReceiveNotificationResponse:withCompletionHandler:))]
        fn did_receive(
            &self,
            _center: &UNUserNotificationCenter,
            response: &UNNotificationResponse,
            handler: &block2::DynBlock<dyn Fn()>,
        ) {
            let id = response.notification().request().identifier().to_string();
            *CLICKED.lock().unwrap() = Some(id);
            handler.call(());
        }
    }
);

impl NotificationDelegate {
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

thread_local! {
    static DELEGATE: std::cell::RefCell<Option<Retained<NotificationDelegate>>> =
        const { std::cell::RefCell::new(None) };
}

/// Sets the click delegate and asks for permission. Err when the process has no bundle.
pub fn notifications_init(report: impl Fn(String) + Send + Sync + 'static) -> Result<(), String> {
    if bundle_id().is_none() {
        return Err("no bundle identifier: run from the .app bundle".into());
    }
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let delegate = NotificationDelegate::new();
    center.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    DELEGATE.with(|d| *d.borrow_mut() = Some(delegate));
    let block = RcBlock::new(move |granted: Bool, err: *mut NSError| {
        let err = unsafe { err.as_ref() }.map(|e| e.localizedDescription().to_string());
        report(format!(
            "notification permission: granted={} error={err:?}",
            granted.as_bool()
        ));
    });
    center.requestAuthorizationWithOptions_completionHandler(
        UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
        &block,
    );
    Ok(())
}

pub fn notify(id: &str, title: &str, body: &str) -> Result<(), String> {
    let center = UNUserNotificationCenter::currentNotificationCenter();
    let content = UNMutableNotificationContent::new();
    content.setTitle(&NSString::from_str(title));
    content.setBody(&NSString::from_str(body));
    let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
        &NSString::from_str(id),
        &content,
        None,
    );
    center.addNotificationRequest_withCompletionHandler(&request, None);
    Ok(())
}
