// © 2026 aiaiaiai · aiaiaiai.org
// SPDX-License-Identifier: Apache-2.0
//! The base location AIS shares across the family: one H3 cell at resolution
//! 8 (a few city blocks). A product's precise position never reaches AIS; 0x1
//! reports only the cell it is in, and only when that cell changes.

use std::{fmt, str::FromStr};

use h3o::{CellIndex, Resolution};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The only resolution AIS accepts or stores (owner decision, 2026-11-23).
pub const RESOLUTION: Resolution = Resolution::Eight;

/// A valid H3 cell at [`RESOLUTION`], written as its canonical 15-digit
/// lowercase hex index, e.g. `881e6384a3fffff`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct H3Cell(CellIndex);

impl FromStr for H3Cell {
    type Err = InvalidCell;

    fn from_str(value: &str) -> Result<Self, InvalidCell> {
        // Canonical form only: the stored text and every response must be
        // byte-identical for the same cell.
        if value.len() != 15
            || !value
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(InvalidCell);
        }
        let index = u64::from_str_radix(value, 16).map_err(|_| InvalidCell)?;
        let cell = CellIndex::try_from(index).map_err(|_| InvalidCell)?;
        if cell.resolution() != RESOLUTION {
            return Err(InvalidCell);
        }
        Ok(Self(cell))
    }
}

impl fmt::Display for H3Cell {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{:x}", u64::from(self.0))
    }
}

#[derive(Debug, thiserror::Error)]
#[error("not an H3 cell at resolution 8")]
pub struct InvalidCell;

impl Serialize for H3Cell {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for H3Cell {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        String::deserialize(decoder)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_canonical_resolution_8_cells() {
        // Kyiv, Maidan Nezalezhnosti.
        let kyiv = h3o::LatLng::new(50.4501, 30.5234)
            .unwrap()
            .to_cell(RESOLUTION);
        let text = format!("{:x}", u64::from(kyiv));
        let cell: H3Cell = text.parse().unwrap();
        assert_eq!(cell.to_string(), text);

        let coarser = format!("{:x}", u64::from(kyiv.parent(Resolution::Seven).unwrap()));
        let finer = format!(
            "{:x}",
            u64::from(kyiv.center_child(Resolution::Nine).unwrap())
        );
        for refused in [
            coarser.as_str(),
            finer.as_str(),
            &text.to_uppercase(),
            "8fffffffffffffff",
            "",
            "not-a-cell",
            "504500000,305234000",
        ] {
            assert!(refused.parse::<H3Cell>().is_err(), "{refused}");
        }
    }
}
