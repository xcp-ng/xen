use core::{marker::PhantomData, str::FromStr};

use enumflags2::{BitFlag, BitFlags};
use serde::{Deserializer, Serializer, de::Visitor, ser::SerializeSeq};

pub fn serialize<'ser, F, S>(v: &BitFlags<F>, s: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    F: BitFlag + AsRef<str>,
{
    let mut seq = s.serialize_seq(Some(v.len()))?;

    for flag in *v {
        seq.serialize_element(flag.as_ref())?;
    }

    seq.end()
}

struct UnpackedBitFieldVisitor<F: BitFlag + strum::VariantNames + FromStr>(
    PhantomData<BitFlags<F>>,
);

impl<'de, F> Visitor<'de> for UnpackedBitFieldVisitor<F>
where
    F: BitFlag + strum::VariantNames + FromStr,
{
    type Value = BitFlags<F>;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a string among ")?;
        formatter.debug_list().entries(F::VARIANTS).finish()
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut flags = BitFlags::empty();

        while let Some(entry) = seq.next_element::<&'de str>()? {
            if let Ok(val) = entry.parse::<F>() {
                flags |= val;
            }
        }

        Ok(flags)
    }
}

pub fn deserialize<'de, F, D>(d: D) -> Result<BitFlags<F>, D::Error>
where
    D: Deserializer<'de>,
    F: BitFlag + strum::VariantNames + FromStr,
{
    d.deserialize_seq(UnpackedBitFieldVisitor(PhantomData))
}
