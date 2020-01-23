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

/// The conversion from coin to raw value
const COIN_TO_RAW_POWER_OF_10_CONVERSION: u32 = 9;

/// The conversion from coin to raw value
const COIN_TO_RAW_CONVERSION: u64 = 1_000_000_000;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
/// Structure representing a safecoin amount.
pub struct Coins(u64);

impl Coins {
    /// New value from a number of nano coin.
    pub const fn from_nano(value: u64) -> Self {
        Self(value)
    }

    /// Total coin expressed in number of nano coin.
    pub const fn as_nano(self) -> u64 {
        self.0
    }

    /// Computes `self + rhs`, returning `None` if overflow occurred.
    pub fn checked_add(self, rhs: Coins) -> Option<Coins> {
        self.0.checked_add(rhs.0).map(Self::from_nano)
    }

    /// Computes `self - rhs`, returning `None` if overflow occurred.
    pub fn checked_sub(self, rhs: Coins) -> Option<Coins> {
        self.0.checked_sub(rhs.0).map(Self::from_nano)
    }
}

impl FromStr for Coins {
    type Err = Error;

    fn from_str(value_str: &str) -> Result<Self> {
        let mut itr = value_str.splitn(2, '.');
        let converted_units = {
            let units = itr
                .next()
                .and_then(|s| s.parse::<u64>().ok())
                .ok_or_else(|| Error::FailedToParse("Can't parse coin units".to_string()))?;

            units
                .checked_mul(COIN_TO_RAW_CONVERSION)
                .ok_or_else(|| Error::ExcessiveValue)?
        };

        let remainder = {
            let remainder_str = itr.next().unwrap_or_default().trim_end_matches('0');

            if remainder_str.is_empty() {
                0
            } else {
                let parsed_remainder = remainder_str
                    .parse::<u64>()
                    .map_err(|_| Error::FailedToParse("Can't parse coin remainder".to_string()))?;

                let remainder_conversion = COIN_TO_RAW_POWER_OF_10_CONVERSION
                    .checked_sub(remainder_str.len() as u32)
                    .ok_or_else(|| Error::LossOfPrecision)?;
                parsed_remainder * 10_u64.pow(remainder_conversion)
            }
        };

        Ok(Self::from_nano(converted_units + remainder))
    }
}

impl Debug for Coins {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {

        Display::fmt(self, formatter)
    }
}

impl Display for Coins {
    fn fmt(&self, formatter: &mut Formatter) -> fmt::Result {
        let unit = self.0 / COIN_TO_RAW_CONVERSION;
        let remainder = self.0 % COIN_TO_RAW_CONVERSION;
        write!(formatter, "{}.{}", unit, format!("{:09}", remainder))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::u64;
    use unwrap::unwrap;

    #[test]
    fn from_str() {
        assert_eq!(Coins(0), unwrap!(Coins::from_str("0")));
        assert_eq!(Coins(0), unwrap!(Coins::from_str("0.")));
        assert_eq!(Coins(0), unwrap!(Coins::from_str("0.0")));
        assert_eq!(Coins(1), unwrap!(Coins::from_str("0.000000001")));
        assert_eq!(Coins(1_000_000_000), unwrap!(Coins::from_str("1")));
        assert_eq!(Coins(1_000_000_000), unwrap!(Coins::from_str("1.")));
        assert_eq!(Coins(1_000_000_000), unwrap!(Coins::from_str("1.0")));
        assert_eq!(
            Coins(1_000_000_001),
            unwrap!(Coins::from_str("1.000000001"))
        );
        assert_eq!(Coins(1_100_000_000), unwrap!(Coins::from_str("1.1")));
        assert_eq!(
            Coins(1_100_000_001),
            unwrap!(Coins::from_str("1.100000001"))
        );
        assert_eq!(
            Coins(4_294_967_295_000_000_000),
            unwrap!(Coins::from_str("4294967295"))
        );
        assert_eq!(
            Coins(4_294_967_295_999_999_999),
            unwrap!(Coins::from_str("4294967295.999999999")),
        );
        assert_eq!(
            Coins(4_294_967_295_999_999_999),
            unwrap!(Coins::from_str("4294967295.9999999990000")),
        );

        assert_eq!(
            Err(Error::FailedToParse("Can't parse coin units".to_string())),
            Coins::from_str("a")
        );
        assert_eq!(
            Err(Error::FailedToParse(
                "Can't parse coin remainder".to_string()
            )),
            Coins::from_str("0.a")
        );
        assert_eq!(
            Err(Error::FailedToParse(
                "Can't parse coin remainder".to_string()
            )),
            Coins::from_str("0.0.0")
        );
        assert_eq!(Err(Error::LossOfPrecision), Coins::from_str("0.0000000009"));
        assert_eq!(Err(Error::ExcessiveValue), Coins::from_str("18446744074"));
    }

    #[test]
    fn display() {
        assert_eq!("0.000000000", format!("{}", Coins(0)));
        assert_eq!("0.000000001", format!("{}", Coins(1)));
        assert_eq!("0.000000010", format!("{}", Coins(10)));
        assert_eq!("1.000000000", format!("{}", Coins(1_000_000_000)));
        assert_eq!("1.000000001", format!("{}", Coins(1_000_000_001)));
        assert_eq!(
            "4294967295.000000000",
            format!("{}", Coins(4_294_967_295_000_000_000))
        );
    }

    #[test]
    fn checked_add_sub() {
        assert_eq!(Some(Coins(3)), Coins(1).checked_add(Coins(2)));
        assert_eq!(None, Coins(u64::MAX).checked_add(Coins(1)));
        assert_eq!(None, Coins(u64::MAX).checked_add(Coins(u64::MAX)));

        assert_eq!(Some(Coins(0)), Coins(u64::MAX).checked_sub(Coins(u64::MAX)));
        assert_eq!(None, Coins(0).checked_sub(Coins(u64::MAX)));
        assert_eq!(None, Coins(10).checked_sub(Coins(11)));
    }
}
