pub mod artifacts;
pub mod delegation;
pub mod domain;
pub mod events;
pub mod identity;
pub mod permissions;
pub mod persistence;
pub mod recovery;
pub mod tasks;

#[cfg(test)]
mod tests {
    #[test]
    fn kernel_library_loads() {
        assert_eq!(2 + 2, 4);
    }
}
