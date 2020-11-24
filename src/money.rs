// Copyright 2019 MaidSafe.net limited.
//
// This SAFE Network Software is licensed to you under the MIT license <LICENSE-MIT
// https://opensource.org/licenses/MIT> or the Modified BSD license <LICENSE-BSD
// https://opensource.org/licenses/BSD-3-Clause>, at your option. This file may not be copied,
// modified, or distributed except according to those terms. Please review the Licences for the
// specific language governing permissions and limitations relating to use of the SAFE Network
// Software.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Debug, Display, Formatter},
    str::FromStr,
};

/// The conversion from Money to raw value
const MONEY_TO_RAW_POWER_OF_10_CONVERSION: u32 = 9;

/// The conversion from Money to raw value
const MONEY_TO_RAW_CONVERSION: u64 = 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
/// Structure representing a safeMoney amount.
pub struct Money(u64);

impl Money {
    /// Type safe representation of zero Money.
    pub const fn zero() -> Self {
        Self(0)
    }

    /// New value from a number of nano Money.
    pub const fn from_nano(value: u64) -> Self {
        Self(value)
    }

    /// Total Money expressed in number of nano Money.
    pub const fn as_nano(self) -> u64 {
        self.0
    }

    /// Computes `self + rhs`, returning `None` if overflow occurred.
    pub fn checked_add(self, rhs: Money) -> Option<Money> {
        self.0.checked_add(rhs.0).map(Self::from_nano)
    }

    /// Computes `self - rhs`, returning `None` if overflow occurred.
    pub fn checked_sub(self, rhs: Money) -> Option<Money> {
        self.0.checked_sub(rhs.0).map(Self::from_nano)
    }
}

impl FromStr for Money {
    type Err = Error;

    fn from_str(value_str: &str) -> Result<Self> {
        let mut itr = value_str.splitn(2, '.');
        let converted_units = {
            let units = itr
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| Error::FailedToParse("Can't parse Money units".to_string()))?;

            units
                .checked_mul(MONEY_TO_RAW_CONVERSION)
                .ok_or(Error::ExcessiveValue)?
        };

        let remainder = {
            let remainder_str = itr.next().unwrap_or_default().trim_end_matches('0');

            if remainder_str.is_empty() {
                0
            } else {
                let parsed_remainder = remainder_str
                    .parse::<u64>()
                    .map_err(|_| Error::FailedToParse("Can't parse Money remainder".to_string()))?;

                let remainder_conversion = MONEY_TO_RAW_POWER_OF_10_CONVERSION
                    .checked_sub(remainder_str.len() as u32)
                    .ok_or(Error::LossOfPrecision)?;
                parsed_remainder * 10_u64.pow(remainder_conversion)
            }
        };

        Ok(Self::from_nano(converted_units + remainder))
    }
}

impl Debug for Money {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        Display::fmt(self, formatter)
    }
}

impl Display for Money {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let unit = self.0 / MONEY_TO_RAW_CONVERSION;
        let remainder = self.0 % MONEY_TO_RAW_CONVERSION;
        write!(formatter, "{}.{}", unit, format!("{:09}", remainder))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::u64;

    #[test]
    fn from_str() -> Result<()> {
        assert_eq!(Money(0), Money::from_str("0")?);
        assert_eq!(Money(0), Money::from_str("0.")?);
        assert_eq!(Money(0), Money::from_str("0.0")?);
        assert_eq!(Money(1), Money::from_str("0.000000001")?);
        assert_eq!(Money(1_000_000_000), Money::from_str("1")?);
        assert_eq!(Money(1_000_000_000), Money::from_str("1.")?);
        assert_eq!(Money(1_000_000_000), Money::from_str("1.0")?);
        assert_eq!(Money(1_000_000_001), Money::from_str("1.000000001")?);
        assert_eq!(Money(1_100_000_000), Money::from_str("1.1")?);
        assert_eq!(Money(1_100_000_001), Money::from_str("1.100000001")?);
        assert_eq!(
            Money(4_294_967_295_000_000_000),
            Money::from_str("4294967295")?
        );
        assert_eq!(
            Money(4_294_967_295_999_999_999),
            Money::from_str("4294967295.999999999")?,
        );
        assert_eq!(
            Money(4_294_967_295_999_999_999),
            Money::from_str("4294967295.9999999990000")?,
        );

        assert_eq!(
            Err(Error::FailedToParse("Can't parse Money units".to_string())),
            Money::from_str("a")
        );
        assert_eq!(
            Err(Error::FailedToParse(
                "Can't parse Money remainder".to_string()
            )),
            Money::from_str("0.a")
        );
        assert_eq!(
            Err(Error::FailedToParse(
                "Can't parse Money remainder".to_string()
            )),
            Money::from_str("0.0.0")
        );
        assert_eq!(Err(Error::LossOfPrecision), Money::from_str("0.0000000009"));
        assert_eq!(Err(Error::ExcessiveValue), Money::from_str("18446744074"));
        Ok(())
    }

    #[test]
    fn display() {
        assert_eq!("0.000000000", format!("{}", Money(0)));
        assert_eq!("0.000000001", format!("{}", Money(1)));
        assert_eq!("0.000000010", format!("{}", Money(10)));
        assert_eq!("1.000000000", format!("{}", Money(1_000_000_000)));
        assert_eq!("1.000000001", format!("{}", Money(1_000_000_001)));
        assert_eq!(
            "4294967295.000000000",
            format!("{}", Money(4_294_967_295_000_000_000))
        );
    }

    #[test]
    fn checked_add_sub() {
        assert_eq!(Some(Money(3)), Money(1).checked_add(Money(2)));
        assert_eq!(None, Money(u64::MAX).checked_add(Money(1)));
        assert_eq!(None, Money(u64::MAX).checked_add(Money(u64::MAX)));

        assert_eq!(Some(Money(0)), Money(u64::MAX).checked_sub(Money(u64::MAX)));
        assert_eq!(None, Money(0).checked_sub(Money(u64::MAX)));
        assert_eq!(None, Money(10).checked_sub(Money(11)));
    }
}
