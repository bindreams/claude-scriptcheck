pub mod canonicalize;
pub mod checker;
pub mod cli;
pub mod cmd_parser;
pub mod file_access;
pub mod hook;
pub mod logging;
pub mod permission;
pub mod settings;

#[cfg(test)]
mod canonicalize_tests;
#[cfg(test)]
mod checker_tests;
#[cfg(test)]
mod cli_tests;
#[cfg(test)]
mod cmd_parser_tests;
#[cfg(test)]
mod file_access_tests;
#[cfg(test)]
mod permission_tests;
#[cfg(test)]
mod settings_tests;
