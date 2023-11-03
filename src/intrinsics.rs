#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
pub use self::aarch64::*;

#[cfg(feature = "portable")]
pub use self::portable::*;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(feature = "portable")))]
pub use self::x86_64::*;

#[cfg(all(target_arch = "aarch64", not(feature = "portable")))]
mod aarch64;

#[cfg(feature = "portable")]
mod portable;

#[cfg(all(any(target_arch = "x86_64", target_arch = "x86"), not(feature = "portable")))]
mod x86_64;
