//! `OrderedMap`'s `serde` impls, shared by the JSON and YAML encodings.
//!
//! serde has one `Serialize`/`Deserialize` pair covering every format, so the JSON- and
//! YAML-shaped implementations both land on these two impls. The YAML-shaped key handling that
//! encodes each key as a node lives in `yaml.rs`.

use std::fmt;
use std::hash::Hash;
use std::marker::PhantomData;

use serde::de::{DeserializeOwned, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::orderedmap::OrderedMap;
use super::yaml::decode_key;

impl<K: Eq + Hash + Serialize, V: Serialize> Serialize for OrderedMap<K, V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.len()))?;

        let mut pair = self.oldest();
        while let Some(current) = pair {
            map.serialize_entry(current.key(), current.value())?;
            pair = current.next();
        }

        map.end()
    }
}

impl<'de, K, V> Deserialize<'de> for OrderedMap<K, V>
where
    K: Eq + Hash + Clone + DeserializeOwned,
    V: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_map(OrderedMapVisitor { marker: PhantomData })
    }
}

struct OrderedMapVisitor<K, V> {
    marker: PhantomData<(K, V)>,
}

impl<'de, K, V> Visitor<'de> for OrderedMapVisitor<K, V>
where
    K: Eq + Hash + Clone + DeserializeOwned,
    V: Deserialize<'de>,
{
    type Value = OrderedMap<K, V>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a map")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut ordered_map = OrderedMap::new();
        while let Some(key_value) = map.next_key::<serde_yaml::Value>()? {
            let key: K = decode_key(key_value)?;
            let value: V = map.next_value()?;
            ordered_map.set(key, value);
        }
        Ok(ordered_map)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt::Debug;

    use serde::de;
    use serde_json::ser::PrettyFormatter;
    use serde_json::{json, Value};

    use super::*;
    use crate::orderedmap::orderedmap::tests::{assert_len_equal, assert_ordered_pairs_equal, key_strings};

    // The special-character string, shared with the YAML tests.
    pub(crate) const SPECIAL_CHARACTERS: &str = "\u{ffff}\u{fffd}世界\u{7f}\u{ff}\u{10ffff}";

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub(crate) struct Marshallable(pub(crate) i32);

    impl Marshallable {
        fn parse(text: &str) -> Result<Self, String> {
            if text.len() < 3 {
                return Err("too short".to_owned());
            }
            if !text.starts_with('#') || !text.ends_with('#') {
                return Err("missing prefix or suffix".to_owned());
            }

            let value = text[1..text.len() - 1].parse::<i32>().map_err(|err| err.to_string())?;

            Ok(Marshallable(value))
        }
    }

    impl Serialize for Marshallable {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.serialize_str(&format!("#{}#", self.0))
        }
    }

    impl<'de> Deserialize<'de> for Marshallable {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            let text = String::deserialize(deserializer)?;
            Marshallable::parse(&text).map_err(de::Error::custom)
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub(crate) struct MyString(pub(crate) String);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
    #[serde(transparent)]
    pub(crate) struct MyInt(pub(crate) u32);

    #[derive(Debug, Serialize, Deserialize)]
    pub(crate) struct NestedMaps {
        x: i32,
        m: OrderedMap<String, Vec<OrderedMap<i32, OrderedMap<String, Value>>>>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub(crate) struct TestFuzzStruct {
        m1: Option<OrderedMap<i32, Value>>,
        m2: Option<OrderedMap<i32, String>>,
        m3: Option<OrderedMap<String, String>>,
    }

    pub(crate) const JSON_CORPUS: &[&str] = &[
        "{}",
        "[]",
        "null",
        "true",
        "1",
        "\"x\"",
        "{\"a\":\"b\"}",
        "{\"a\":1}",
        "{\"a\":null}",
        "{\"a\":[1,2,3]}",
        "{\"a\":{\"b\":{\"c\":\"d\"}}}",
        "{\"a\":\"b\",\"a\":\"c\"}",
        "{\"1\":2}",
        "{\"\":\"\"}",
        "{\"a\":1.5}",
        "{\"a\":true,\"b\":false,\"c\":null}",
    ];

    #[test]
    fn test_marshal_json() {
        let mut om = OrderedMap::<i32, Value>::new();
        om.set(1, json!("bar"));
        om.set(7, json!("baz"));
        om.set(2, json!(28));
        om.set(3, json!(100));
        om.set(4, json!("baz"));
        om.set(5, json!("28"));
        om.set(6, json!("100"));
        om.set(8, json!("baz"));
        om.set(8, json!("baz"));
        om.set(9, json!("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque auctor augue accumsan mi maximus, quis viverra massa pretium. Phasellus imperdiet sapien a interdum sollicitudin. Duis at commodo lectus, a lacinia sem."));

        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(
            r#"{"1":"bar","7":"baz","2":28,"3":100,"4":"baz","5":"28","6":"100","8":"baz","9":"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque auctor augue accumsan mi maximus, quis viverra massa pretium. Phasellus imperdiet sapien a interdum sollicitudin. Duis at commodo lectus, a lacinia sem."}"#,
            b
        );
    }

    #[test]
    fn test_marshal_json_string_key() {
        let mut om = OrderedMap::<String, Value>::new();
        om.set("test".to_owned(), json!("bar"));
        om.set("abc".to_owned(), json!(true));

        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(r#"{"test":"bar","abc":true}"#, b);
    }

    #[test]
    fn test_marshal_json_typed_string_key() {
        let mut om = OrderedMap::<MyString, Value>::new();
        om.set(MyString("test".to_owned()), json!("bar"));
        om.set(MyString("abc".to_owned()), json!(true));

        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(r#"{"test":"bar","abc":true}"#, b);
    }

    #[test]
    fn test_marshal_json_typed_int_key() {
        let mut om = OrderedMap::<MyInt, Value>::new();
        om.set(MyInt(1), json!("bar"));
        om.set(MyInt(7), json!("baz"));
        om.set(MyInt(2), json!(28));
        om.set(MyInt(3), json!(100));
        om.set(MyInt(4), json!("baz"));

        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(r#"{"1":"bar","7":"baz","2":28,"3":100,"4":"baz"}"#, b);
    }

    #[test]
    fn test_marshal_json_text_marshaller_key() {
        let mut om = OrderedMap::<Marshallable, Value>::new();
        om.set(Marshallable(1), json!("bar"));
        om.set(Marshallable(28), json!(true));

        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(r##"{"#1#":"bar","#28#":true}"##, b);
    }

    #[test]
    fn test_marshal_json_empty_map() {
        let om = OrderedMap::<String, Value>::new();

        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(r#"{}"#, b);
    }

    #[test]
    fn test_unmarshal_json() {
        let data = r#"{"1":"bar","7":"baz","2":28,"3":100,"4":"baz","5":"28","6":"100","8":"baz"}"#;

        let om: OrderedMap<i32, Value> = serde_json::from_str(data).unwrap();

        assert_ordered_pairs_equal(
            &om,
            &[1, 7, 2, 3, 4, 5, 6, 8],
            &[json!("bar"), json!("baz"), json!(28), json!(100), json!("baz"), json!("28"), json!("100"), json!("baz")],
        );
    }

    #[test]
    fn test_unmarshal_json_string_key() {
        let data = r#"{"test":"bar","abc":true}"#;

        let om: OrderedMap<String, Value> = serde_json::from_str(data).unwrap();

        assert_ordered_pairs_equal(&om, &key_strings(["test", "abc"]), &[json!("bar"), json!(true)]);
    }

    #[test]
    fn test_unmarshal_json_typed_string_key() {
        let data = r#"{"test":"bar","abc":true}"#;

        let om: OrderedMap<MyString, Value> = serde_json::from_str(data).unwrap();

        assert_ordered_pairs_equal(
            &om,
            &[MyString("test".to_owned()), MyString("abc".to_owned())],
            &[json!("bar"), json!(true)],
        );
    }

    #[test]
    fn test_unmarshal_json_typed_int_key() {
        let data = r#"{"1":"bar","7":"baz","2":28,"3":100,"4":"baz","5":"28","6":"100","8":"baz"}"#;

        let om: OrderedMap<MyInt, Value> = serde_json::from_str(data).unwrap();

        assert_ordered_pairs_equal(
            &om,
            &[MyInt(1), MyInt(7), MyInt(2), MyInt(3), MyInt(4), MyInt(5), MyInt(6), MyInt(8)],
            &[json!("bar"), json!("baz"), json!(28), json!(100), json!("baz"), json!("28"), json!("100"), json!("baz")],
        );
    }

    #[test]
    fn test_unmarshal_json_text_unmarshaler_key() {
        let data = r##"{"#1#":"bar","#28#":true}"##;

        let om: OrderedMap<Marshallable, Value> = serde_json::from_str(data).unwrap();

        assert_ordered_pairs_equal(&om, &[Marshallable(1), Marshallable(28)], &[json!("bar"), json!(true)]);
    }

    #[test]
    fn test_unmarshal_json_not_an_object() {
        for data in ["true", r#"["foo"]"#, "42", r#""foo""#] {
            let om = serde_json::from_str::<OrderedMap<i32, Value>>(data);
            assert!(om.is_err(), "expected an error for {data}");
        }
    }

    #[test]
    fn test_unmarshal_json_empty_map() {
        let data = "{}";

        let om: OrderedMap<i32, Value> = serde_json::from_str(data).unwrap();

        assert_len_equal(&om, 0);
    }

    #[test]
    fn test_json_special_characters() {
        let baseline_map = serde_json::Map::from_iter([(SPECIAL_CHARACTERS.to_owned(), json!(SPECIAL_CHARACTERS))]);
        let baseline_data = serde_json::to_string(&baseline_map).unwrap();

        let mut om = OrderedMap::<String, Value>::new();
        om.set(SPECIAL_CHARACTERS.to_owned(), json!(SPECIAL_CHARACTERS));
        let b = serde_json::to_string(&om).unwrap();
        assert_eq!(baseline_data, b);

        let mut om2 = OrderedMap::<MyString, MyString>::new();
        om2.set(MyString(SPECIAL_CHARACTERS.to_owned()), MyString(SPECIAL_CHARACTERS.to_owned()));
        let b = serde_json::to_string(&om2).unwrap();
        assert_eq!(baseline_data, b);

        let om: OrderedMap<String, Value> = serde_json::from_str(&baseline_data).unwrap();
        assert_ordered_pairs_equal(&om, &key_strings([SPECIAL_CHARACTERS]), &[json!(SPECIAL_CHARACTERS)]);

        let om2: OrderedMap<MyString, MyString> = serde_json::from_str(&baseline_data).unwrap();
        assert_ordered_pairs_equal(
            &om2,
            &[MyString(SPECIAL_CHARACTERS.to_owned())],
            &[MyString(SPECIAL_CHARACTERS.to_owned())],
        );
    }

    #[test]
    fn test_json_round_trip() {
        let nested_input = r#"{
    "x": 28,
    "m": {
        "foo": [
            {
                "12": {
                    "i": 12,
                    "b": true,
                    "n": null,
                    "m": {
                        "a": "b",
                        "c": 28
                    }
                },
                "28": {
                    "a": false,
                    "b": [
                        1,
                        2,
                        3
                    ]
                }
            },
            {
                "3": {
                    "c": null,
                    "d": 87
                },
                "4": {
                    "e": true
                },
                "5": {
                    "f": 4,
                    "g": 5,
                    "h": 6
                }
            }
        ],
        "bar": [
            {
                "5": {
                    "foo": "bar"
                }
            }
        ]
    }
}"#;

        let target: NestedMaps = serde_json::from_str(nested_input).unwrap();
        let mut out = Vec::new();
        let mut serializer = serde_json::Serializer::with_formatter(&mut out, PrettyFormatter::with_indent(b"    "));
        target.serialize(&mut serializer).unwrap();
        assert_eq!(nested_input.trim(), String::from_utf8(out).unwrap());

        let special_input = r#"{"�":0}"#;
        let target: OrderedMap<String, i32> = serde_json::from_str(special_input).unwrap();
        assert_eq!(special_input.trim(), serde_json::to_string(&target).unwrap());
    }

    #[test]
    fn test_round_trip_json_fuzz_corpus() {
        round_trip_json_maps::<String, String>();
        round_trip_json_maps::<String, i32>();
        round_trip_json_maps::<String, Value>();
        round_trip_json_structs();
    }

    fn round_trip_json_maps<K, V>()
    where
        K: Eq + Hash + Clone + DeserializeOwned + Serialize + Debug,
        V: DeserializeOwned + Serialize + PartialEq + Debug,
    {
        for data in JSON_CORPUS {
            let Ok(v1) = serde_json::from_str::<OrderedMap<K, V>>(data) else {
                continue;
            };

            let json_data = serde_json::to_string(&v1).unwrap();

            let v2: OrderedMap<K, V> = serde_json::from_str(&json_data).unwrap();

            assert!(assert_ordered_maps_equal(&v1, &v2), "failed with input data {data:?}");
        }
    }

    fn round_trip_json_structs() {
        for data in JSON_CORPUS {
            let Ok(v1) = serde_json::from_str::<TestFuzzStruct>(data) else {
                continue;
            };

            let json_data = serde_json::to_string(&v1).unwrap();

            let v2: TestFuzzStruct = serde_json::from_str(&json_data).unwrap();

            assert!(assert_test_fuzz_struct_equal(&v1, &v2), "failed with input data {data:?}");
        }
    }

    pub(crate) fn assert_test_fuzz_struct_equal(v1: &TestFuzzStruct, v2: &TestFuzzStruct) -> bool {
        let success = assert_optional_ordered_maps_equal(&v1.m1, &v2.m1);
        let success = assert_optional_ordered_maps_equal(&v1.m2, &v2.m2) && success;
        assert_optional_ordered_maps_equal(&v1.m3, &v2.m3) && success
    }

    fn assert_optional_ordered_maps_equal<K, V>(v1: &Option<OrderedMap<K, V>>, v2: &Option<OrderedMap<K, V>>) -> bool
    where
        K: PartialEq + Debug,
        V: PartialEq + Debug,
    {
        match (v1, v2) {
            (Some(v1), Some(v2)) => assert_ordered_maps_equal(v1, v2),
            (None, None) => true,
            _ => {
                assert_eq!(v1.is_some(), v2.is_some(), "one map is missing");
                false
            }
        }
    }

    pub(crate) fn assert_ordered_maps_equal<K, V>(om1: &OrderedMap<K, V>, om2: &OrderedMap<K, V>) -> bool
    where
        K: PartialEq + Debug,
        V: PartialEq + Debug,
    {
        let mut success = om1.len() == om2.len();

        let mut pair1 = om1.oldest();
        let mut pair2 = om2.oldest();
        while let (Some(pair1_current), Some(pair2_current)) = (pair1, pair2) {
            let same_key = pair1_current.key() == pair2_current.key();
            let same_value = pair1_current.value() == pair2_current.value();
            success = success && same_key && same_value;

            pair1 = pair1_current.next();
            pair2 = pair2_current.next();
        }

        success
    }
}
