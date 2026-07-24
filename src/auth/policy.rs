use crate::error::AppError;

pub fn authorize(ns: &str, operation: &str) -> Result<(), AppError> {
    let _ = ns;
    let _ = operation;
    Ok(())
}
