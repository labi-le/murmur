use std::fmt;

use tokio_util::sync::CancellationToken;

use super::level::LogLevel;
use super::log::{fatal_line, log_line};

/// Levelled logging interface.
pub trait Logger: Send + Sync {
    fn trace(&self, args: fmt::Arguments<'_>);
    fn debug(&self, args: fmt::Arguments<'_>);
    fn info(&self, args: fmt::Arguments<'_>);
    fn warn(&self, args: fmt::Arguments<'_>);
    fn error(&self, args: fmt::Arguments<'_>);
    fn fatal(&self, args: fmt::Arguments<'_>);
    fn panic(&self, args: fmt::Arguments<'_>);
}

/// Logger that also emits against a cancellation context.
pub trait ContextLogger: Logger {
    fn trace_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
    fn debug_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
    fn info_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
    fn warn_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
    fn error_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
    fn fatal_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
    fn panic_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SingLogger;

impl Logger for SingLogger {
    fn trace(&self, args: fmt::Arguments<'_>) {
        log_line(LogLevel::DEBUG, args.to_string());
    }

    fn debug(&self, args: fmt::Arguments<'_>) {
        log_line(LogLevel::DEBUG, args.to_string());
    }

    fn info(&self, args: fmt::Arguments<'_>) {
        log_line(LogLevel::INFO, args.to_string());
    }

    fn warn(&self, args: fmt::Arguments<'_>) {
        log_line(LogLevel::WARNING, args.to_string());
    }

    fn error(&self, args: fmt::Arguments<'_>) {
        log_line(LogLevel::ERROR, args.to_string());
    }

    fn fatal(&self, args: fmt::Arguments<'_>) {
        fatal_line(args.to_string());
    }

    fn panic(&self, args: fmt::Arguments<'_>) {
        fatal_line(args.to_string());
    }
}

impl ContextLogger for SingLogger {
    fn trace_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        log_line(LogLevel::DEBUG, args.to_string());
    }

    fn debug_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        log_line(LogLevel::DEBUG, args.to_string());
    }

    fn info_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        log_line(LogLevel::INFO, args.to_string());
    }

    fn warn_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        log_line(LogLevel::WARNING, args.to_string());
    }

    fn error_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        log_line(LogLevel::ERROR, args.to_string());
    }

    fn fatal_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        fatal_line(args.to_string());
    }

    fn panic_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        fatal_line(args.to_string());
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub struct SingInfoToDebugLogger {
    sing_logger: SingLogger,
}

impl SingInfoToDebugLogger {
    /// Returns the default instance.
    #[must_use]
    pub const fn new() -> Self {
        Self { sing_logger: SingLogger }
    }
}

impl Logger for SingInfoToDebugLogger {
    fn trace(&self, args: fmt::Arguments<'_>) {
        self.sing_logger.trace(args);
    }

    fn debug(&self, args: fmt::Arguments<'_>) {
        self.sing_logger.debug(args);
    }

    fn info(&self, args: fmt::Arguments<'_>) {
        log_line(LogLevel::DEBUG, args.to_string());
    }

    fn warn(&self, args: fmt::Arguments<'_>) {
        self.sing_logger.warn(args);
    }

    fn error(&self, args: fmt::Arguments<'_>) {
        self.sing_logger.error(args);
    }

    fn fatal(&self, args: fmt::Arguments<'_>) {
        self.sing_logger.fatal(args);
    }

    fn panic(&self, args: fmt::Arguments<'_>) {
        self.sing_logger.panic(args);
    }
}

impl ContextLogger for SingInfoToDebugLogger {
    fn trace_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        self.sing_logger.trace_context(ctx, args);
    }

    fn debug_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        self.sing_logger.debug_context(ctx, args);
    }

    fn info_context(&self, _ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        log_line(LogLevel::DEBUG, args.to_string());
    }

    fn warn_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        self.sing_logger.warn_context(ctx, args);
    }

    fn error_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        self.sing_logger.error_context(ctx, args);
    }

    fn fatal_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        self.sing_logger.fatal_context(ctx, args);
    }

    fn panic_context(&self, ctx: &CancellationToken, args: fmt::Arguments<'_>) {
        self.sing_logger.panic_context(ctx, args);
    }
}

pub static SING_LOGGER: SingLogger = SingLogger;

pub static SING_INFO_TO_DEBUG_LOGGER: SingInfoToDebugLogger = SingInfoToDebugLogger { sing_logger: SingLogger };
