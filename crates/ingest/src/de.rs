//! Lenient serde helpers. Collector output varies between versions (scalar vs
//! list, bool vs int vs string, wrapped `{"Results":[...]}` vs bare arrays);
//! these accept all of them instead of rejecting the whole record.

use serde::de::{self, Deserializer, IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use std::fmt;
use std::marker::PhantomData;

/// Reference to another object: `"S-1-..."` or `{"ObjectIdentifier":..,"ObjectType":..}`.
#[derive(Debug, Default, Clone)]
pub struct Ref {
    pub id: String,
    pub ty: Option<String>,
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum RefField {
    ObjectIdentifier,
    ObjectType,
    #[serde(other)]
    Other,
}

impl<'de> Deserialize<'de> for Ref {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Ref;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("an object identifier or reference object")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Ref, E> {
                Ok(Ref {
                    id: v.to_owned(),
                    ty: None,
                })
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Ref, E> {
                Ok(Ref { id: v, ty: None })
            }
            fn visit_unit<E: de::Error>(self) -> Result<Ref, E> {
                Ok(Ref::default())
            }
            fn visit_none<E: de::Error>(self) -> Result<Ref, E> {
                Ok(Ref::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Ref, A::Error> {
                let mut r = Ref::default();
                while let Some(k) = m.next_key::<RefField>()? {
                    match k {
                        RefField::ObjectIdentifier => {
                            r.id = m.next_value::<Option<String>>()?.unwrap_or_default()
                        }
                        RefField::ObjectType => r.ty = m.next_value()?,
                        RefField::Other => {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(r)
            }
        }
        d.deserialize_any(V)
    }
}

/// `[...]`, `{"Results":[...], ...}` or `null`.
#[derive(Debug)]
pub struct Results<T>(pub Vec<T>, pub bool);

impl<T> Results<T> {
    /// `{"Collected": true, ...}`: the collector reports this block as
    /// successfully collected (bare arrays and `null` are not).
    pub fn collected(&self) -> bool {
        self.1
    }
}

impl<T> Default for Results<T> {
    fn default() -> Self {
        Results(Vec::new(), false)
    }
}

/// `true` / `"true"` / `1` …, see [`lenient_bool`].
struct LenientBool(Option<bool>);

impl<'de> Deserialize<'de> for LenientBool {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        lenient_bool(d).map(LenientBool)
    }
}

#[derive(Deserialize)]
#[serde(field_identifier)]
enum ResultsField {
    Results,
    Collected,
    #[serde(other)]
    Other,
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Results<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V<T>(PhantomData<T>);
        impl<'de, T: Deserialize<'de>> Visitor<'de> for V<T> {
            type Value = Results<T>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a result list")
            }
            fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(Results(Vec::new(), false))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = s.next_element()? {
                    v.push(x);
                }
                Ok(Results(v, false))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Self::Value, A::Error> {
                let mut v = Vec::new();
                let mut collected = false;
                while let Some(k) = m.next_key::<ResultsField>()? {
                    match k {
                        ResultsField::Results => {
                            v = m.next_value::<Option<Vec<T>>>()?.unwrap_or_default()
                        }
                        ResultsField::Collected => {
                            collected = m.next_value::<LenientBool>()?.0 == Some(true)
                        }
                        ResultsField::Other => {
                            m.next_value::<IgnoredAny>()?;
                        }
                    }
                }
                Ok(Results(v, collected))
            }
        }
        d.deserialize_any(V(PhantomData))
    }
}

/// LDAP-style attribute: a scalar or list of scalars, normalised to strings.
#[derive(Debug, Default, Clone)]
pub struct Many(pub Vec<String>);

impl Many {
    pub fn first(&self) -> Option<&str> {
        self.0.first().map(|s| s.as_str()).filter(|s| !s.is_empty())
    }
    pub fn first_u64(&self) -> Option<u64> {
        self.first().and_then(|s| s.trim().parse().ok())
    }
}

struct Scalar(Option<String>);

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Scalar;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a scalar")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Scalar, E> {
                Ok(Scalar(Some(v.to_owned())))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Scalar, E> {
                Ok(Scalar(Some(v)))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Scalar, E> {
                Ok(Scalar(Some(v.to_string())))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Scalar, E> {
                Ok(Scalar(Some(v.to_string())))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Scalar, E> {
                Ok(Scalar(Some(v.to_string())))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Scalar, E> {
                Ok(Scalar(Some(v.to_string())))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Scalar, E> {
                Ok(Scalar(None))
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Scalar, A::Error> {
                while s.next_element::<IgnoredAny>()?.is_some() {}
                Ok(Scalar(None))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Scalar, A::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Scalar(None))
            }
        }
        d.deserialize_any(V)
    }
}

impl<'de> Deserialize<'de> for Many {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Many;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a scalar or list of scalars")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut s: A) -> Result<Many, A::Error> {
                let mut v = Vec::new();
                while let Some(Scalar(x)) = s.next_element()? {
                    if let Some(x) = x {
                        v.push(x);
                    }
                }
                Ok(Many(v))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Many, E> {
                Ok(Many(vec![v.to_owned()]))
            }
            fn visit_string<E: de::Error>(self, v: String) -> Result<Many, E> {
                Ok(Many(vec![v]))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> Result<Many, E> {
                Ok(Many(vec![v.to_string()]))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> Result<Many, E> {
                Ok(Many(vec![v.to_string()]))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> Result<Many, E> {
                Ok(Many(vec![v.to_string()]))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> Result<Many, E> {
                Ok(Many(vec![v.to_string()]))
            }
            fn visit_unit<E: de::Error>(self) -> Result<Many, E> {
                Ok(Many::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut m: A) -> Result<Many, A::Error> {
                while m.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
                Ok(Many::default())
            }
        }
        d.deserialize_any(V)
    }
}

/// Bool that also accepts 0/1, "true"/"false" and null.
pub fn lenient_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    Ok(Scalar::deserialize(d)?.0.map(|s| {
        let s = s.trim();
        s.eq_ignore_ascii_case("true")
            || (s != "0" && s.parse::<f64>().map(|x| x != 0.0).unwrap_or(false))
    }))
}

/// Any scalar as a string (numbers and bools are stringified; null / lists /
/// objects → `None`).
pub fn lenient_string<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    Ok(Scalar::deserialize(d)?.0)
}

/// Trust direction: 0..=3 or "Disabled"/"Inbound"/"Outbound"/"Bidirectional".
pub fn trust_direction<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u8>, D::Error> {
    Ok(Scalar::deserialize(d)?
        .0
        .and_then(|s| match s.trim().to_ascii_lowercase().as_str() {
            "0" | "disabled" => Some(0),
            "1" | "inbound" => Some(1),
            "2" | "outbound" => Some(2),
            "3" | "bidirectional" => Some(3),
            _ => None,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ref_forms() {
        let v: Vec<Ref> = serde_json::from_str(
            r#"["S-1", {"ObjectIdentifier":"S-2","ObjectType":"User","X":[1]}, null]"#,
        )
        .unwrap();
        assert_eq!(v[0].id, "S-1");
        assert_eq!(v[1].ty.as_deref(), Some("User"));
        assert!(v[2].id.is_empty());
    }

    #[test]
    fn results_forms() {
        let a: Results<Ref> =
            serde_json::from_str(r#"{"Collected":true,"FailureReason":null,"Results":["S-1"]}"#)
                .unwrap();
        let b: Results<Ref> = serde_json::from_str(r#"["S-1","S-2"]"#).unwrap();
        let c: Results<Ref> = serde_json::from_str("null").unwrap();
        assert_eq!((a.0.len(), b.0.len(), c.0.len()), (1, 2, 0));
    }

    #[test]
    fn many_forms() {
        let a: Many = serde_json::from_str(r#"["x", 5, null, true]"#).unwrap();
        assert_eq!(a.0, vec!["x", "5", "true"]);
        let b: Many = serde_json::from_str("66048").unwrap();
        assert_eq!(b.first_u64(), Some(66048));
    }
}
