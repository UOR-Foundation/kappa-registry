// Explicit binary-field codecs preserve Vec-based application APIs while
// ensuring canonical wire maps contain byte strings rather than byte arrays.
macro_rules! wire_map {
    ($name:ident { $($field:ident : $kind:ident = $key:literal),* $(,)? }) => {
        impl From<$name> for dcbor::CBOR {
            fn from(value: $name) -> Self {
                let mut map = dcbor::Map::new();
                $( $crate::wire_map::wire_map!(@put map, value.$field, $kind, $key); )*
                map.into()
            }
        }

        impl TryFrom<dcbor::CBOR> for $name {
            type Error = dcbor::Error;

            fn try_from(cbor: dcbor::CBOR) -> Result<Self, Self::Error> {
                let dcbor::CBORCase::Map(map) = cbor.into_case() else {
                    return Err(dcbor::Error::WrongType);
                };
                for (key, _) in map.iter() {
                    let key: u64 = key.clone().try_into()?;
                    if ![$($key as u64),*].contains(&key) {
                        return Err(dcbor::Error::msg("unknown wire-map field"));
                    }
                }
                Ok(Self {
                    $( $field: $crate::wire_map::wire_map!(@get map, $kind, $key), )*
                })
            }
        }
    };
    (@put $map:ident, $value:expr, value, $key:literal) => {
        $map.insert($key as u64, $value);
    };
    (@put $map:ident, $value:expr, bytes, $key:literal) => {
        $map.insert($key as u64, dcbor::ByteString::from($value));
    };
    (@put $map:ident, $value:expr, optional, $key:literal) => {
        if let Some(value) = $value {
            $map.insert($key as u64, value);
        }
    };
    (@put $map:ident, $value:expr, optional_bytes, $key:literal) => {
        if let Some(value) = $value {
            $map.insert($key as u64, dcbor::ByteString::from(value));
        }
    };
    (@get $map:ident, value, $key:literal) => {
        $map.extract($key as u64)?
    };
    (@get $map:ident, bytes, $key:literal) => {{
        let bytes: dcbor::ByteString = $map.extract($key as u64)?;
        Vec::<u8>::from(bytes)
    }};
    (@get $map:ident, optional, $key:literal) => {{
        if $map.contains_key($key as u64) {
            Some($map.extract($key as u64)?)
        } else {
            None
        }
    }};
    (@get $map:ident, optional_bytes, $key:literal) => {{
        if $map.contains_key($key as u64) {
            let bytes: dcbor::ByteString = $map.extract($key as u64)?;
            Some(Vec::<u8>::from(bytes))
        } else {
            None
        }
    }};
}

pub(crate) use wire_map;
