// Importing necessary modules and traits.
use cron::Schedule;
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

// Using lazy_static to initialize global static variables.
lazy_static! {
    // A static reference to a SessionMap which holds all active sessions.
    static ref SESSIONS: SessionMap = Arc::new(Mutex::new(HashMap::new()));

    // Initializing and starting the cron scheduler.
    static ref CRON_SCHEDULER: CronScheduler = {
        let scheduler = CronScheduler::new(Arc::clone(&SESSIONS));
        scheduler.start();
        scheduler
    };
}

/// Represents a user session.
///
/// # Fields
/// - `user`: A `String` representing the username of the user.
/// - `last_activity`: An `Instant` representing the last activity time of the session.
#[derive(Debug, Clone)]
struct Session {
    user: String,
    last_activity: Instant,
}

// Type alias for a thread-safe, reference-counted session map.
type SessionMap = Arc<Mutex<HashMap<String, Session>>>;

/// Cleans up expired sessions.
///
/// Retains only those sessions which have had activity in the last 30 minutes.
///
/// # Arguments
/// - `sessions`: Reference to the session map to clean up.
fn cleanup_sessions(sessions: &SessionMap) {
    let mut sessions = sessions.lock().unwrap();
    sessions.retain(|_, session| session.last_activity.elapsed() < Duration::from_secs(30 * 60));
    println!("Session cleanup performed");
}

/// A struct for managing a cron scheduler to perform periodic tasks.
struct CronScheduler {
    sessions: SessionMap,
}

impl CronScheduler {
    /// Constructs a new `CronScheduler`.
    ///
    /// # Arguments
    /// - `sessions`: SessionMap that the scheduler will use to perform cleanups.
    fn new(sessions: SessionMap) -> Self {
        Self { sessions }
    }

    /// Starts the cron scheduler.
    ///
    /// Initializes a thread to perform session cleanups every 30 minutes.
    fn start(&self) {
        let sessions_clone = Arc::clone(&self.sessions);

        thread::spawn(move || {
            let expression = "0 0/30 * * * * *"; // Every 30 minutes
            let schedule = Schedule::from_str(expression).unwrap();
            loop {
                for datetime in schedule.upcoming(chrono::Utc).take(1) {
                    let now = chrono::Utc::now();
                    let dur = datetime - now;
                    let std_duration = dur.to_std().unwrap();
                    thread::sleep(std_duration);
                    cleanup_sessions(&sessions_clone); // Call your cleanup function
                }
            }
        });
    }
}

/// Updates or creates a session for a user.
///
/// # Arguments
/// - `user`: A `String` representing the username of the user.
/// - `session_id`: A `String` representing the unique ID of the session.
pub fn update_session(user: String, session_id: String) {
    let mut sessions = SESSIONS.lock().unwrap();
    sessions.insert(
        session_id,
        Session {
            user,
            last_activity: Instant::now(),
        },
    );
}
