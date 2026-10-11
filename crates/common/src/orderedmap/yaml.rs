//! YAML-shaped key encoding and decoding for the ordered map.
//!
//! The map is serialized by building a mapping node whose keys keep their
//! own YAML type, which is what the `Serialize` impl in `json.rs` does by handing each key to the
//! format's map serializer. Deserialization decodes each key node into `K` or
//! parses the key's text; `decode_key` covers both.

use serde::de::{self, DeserializeOwned};
use serde_yaml::Value;

/// Decodes one map key into `K`.
///
/// JSON keys always arrive as strings and are taken as-is when `K` accepts a string; any other key
/// type is parsed from that string. YAML keys keep
/// their node type and are decoded directly.
pub(crate) fn decode_key<K, E>(value: Value) -> Result<K, E>
where
    K: DeserializeOwned,
    E: de::Error,
{
    if let Value::String(text) = &value {
        return serde_yaml::from_value::<K>(Value::String(text.clone()))
            .or_else(|_| serde_yaml::from_str::<K>(text))
            .map_err(|_| E::custom(unsupported_key_message::<K>()));
    }
    serde_yaml::from_value::<K>(value).map_err(|_| E::custom(unsupported_key_message::<K>()))
}

fn unsupported_key_message<K>() -> String {
    format!("unsupported key type: {}", std::any::type_name::<K>())
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fmt::Debug;

    use serde::de::DeserializeOwned;
    use serde::Serialize;
    use serde_json::json;

    use crate::orderedmap::json::tests::{
        assert_ordered_maps_equal, assert_test_fuzz_struct_equal, Marshallable, MyInt, MyString, NestedMaps,
        TestFuzzStruct, SPECIAL_CHARACTERS,
    };
    use crate::orderedmap::orderedmap::tests::{assert_len_equal, assert_ordered_pairs_equal, key_strings};
    use crate::orderedmap::orderedmap::OrderedMap;

    pub(crate) const YAML_CORPUS: &[&str] = &[
        "{}\n",
        "[]\n",
        "null\n",
        "true\n",
        "1\n",
        "x\n",
        "a: b\n",
        "a: 1\n",
        "a: null\n",
        "a:\n    - 1\n    - 2\n",
        "a:\n    b:\n        c: d\n",
        "1: 2\n",
        "a: 1.5\n",
        "m1:\n    1: 2\n",
    ];

    #[test]
    fn test_marshal_yaml_int_key() {
        let mut om = OrderedMap::<i32, serde_json::Value>::new();
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

        let b = serde_yaml::to_string(&om).unwrap();

        let expected = "\
1: bar
7: baz
2: 28
3: 100
4: baz
5: '28'
6: '100'
8: baz
9: Lorem ipsum dolor sit amet, consectetur adipiscing elit. Quisque auctor augue accumsan mi maximus, quis viverra massa pretium. Phasellus imperdiet sapien a interdum sollicitudin. Duis at commodo lectus, a lacinia sem.
";
        assert_eq!(expected, b);
    }

    #[test]
    fn test_marshal_yaml_string_key() {
        let mut om = OrderedMap::<String, serde_json::Value>::new();
        om.set("test".to_owned(), json!("bar"));
        om.set("abc".to_owned(), json!(true));

        let b = serde_yaml::to_string(&om).unwrap();

        let expected = "\
test: bar
abc: true
";
        assert_eq!(expected, b);
    }

    #[test]
    fn test_marshal_yaml_typed_string_key() {
        let mut om = OrderedMap::<MyString, serde_json::Value>::new();
        om.set(MyString("test".to_owned()), json!("bar"));
        om.set(MyString("abc".to_owned()), json!(true));

        let b = serde_yaml::to_string(&om).unwrap();

        let expected = "\
test: bar
abc: true
";
        assert_eq!(expected, b);
    }

    #[test]
    fn test_marshal_yaml_typed_int_key() {
        let mut om = OrderedMap::<MyInt, serde_json::Value>::new();
        om.set(MyInt(1), json!("bar"));
        om.set(MyInt(7), json!("baz"));
        om.set(MyInt(2), json!(28));
        om.set(MyInt(3), json!(100));
        om.set(MyInt(4), json!("baz"));

        let b = serde_yaml::to_string(&om).unwrap();

        let expected = "\
1: bar
7: baz
2: 28
3: 100
4: baz
";
        assert_eq!(expected, b);
    }

    #[test]
    fn test_marshal_yaml_text_marshaller_key() {
        let mut om = OrderedMap::<Marshallable, serde_json::Value>::new();
        om.set(Marshallable(1), json!("bar"));
        om.set(Marshallable(28), json!(true));

        let b = serde_yaml::to_string(&om).unwrap();

        let expected = "\
'#1#': bar
'#28#': true
";
        assert_eq!(expected, b);
    }

    #[test]
    fn test_marshal_yaml_empty_maps() {
        // the zero-valued `&OrderedMap[string, string]{}` has no in-memory counterpart here.
        let om = OrderedMap::<String, serde_json::Value>::new();

        let b = serde_yaml::to_string(&om).unwrap();
        assert_eq!("{}\n", b);

        let om = OrderedMap::<String, String>::new();

        let b = serde_yaml::to_string(&om).unwrap();
        assert_eq!("{}\n", b);
    }

    #[test]
    fn test_unmarshal_yaml_int_key() {
        let data = "\
1: bar
7: baz
2: 28
3: 100
4: baz
5: \"28\"
6: \"100\"
8: baz
";

        let om: OrderedMap<i32, serde_json::Value> = serde_yaml::from_str(data).unwrap();

        assert_ordered_pairs_equal(
            &om,
            &[1, 7, 2, 3, 4, 5, 6, 8],
            &[json!("bar"), json!("baz"), json!(28), json!(100), json!("baz"), json!("28"), json!("100"), json!("baz")],
        );
    }

    #[test]
    fn test_unmarshal_yaml_string_key() {
        let data = r#"{"test":"bar","abc":true}"#;

        let om: OrderedMap<String, serde_json::Value> = serde_yaml::from_str(data).unwrap();

        assert_ordered_pairs_equal(&om, &key_strings(["test", "abc"]), &[json!("bar"), json!(true)]);
    }

    #[test]
    fn test_unmarshal_yaml_typed_string_key() {
        let data = r#"{"test":"bar","abc":true}"#;

        let om: OrderedMap<MyString, serde_json::Value> = serde_yaml::from_str(data).unwrap();

        assert_ordered_pairs_equal(
            &om,
            &[MyString("test".to_owned()), MyString("abc".to_owned())],
            &[json!("bar"), json!(true)],
        );
    }

    #[test]
    fn test_unmarshal_yaml_typed_int_key() {
        let data = "\
1: bar
7: baz
2: 28
3: 100
4: baz
5: \"28\"
6: \"100\"
8: baz
";

        let om: OrderedMap<MyInt, serde_json::Value> = serde_yaml::from_str(data).unwrap();

        assert_ordered_pairs_equal(
            &om,
            &[MyInt(1), MyInt(7), MyInt(2), MyInt(3), MyInt(4), MyInt(5), MyInt(6), MyInt(8)],
            &[json!("bar"), json!("baz"), json!(28), json!(100), json!("baz"), json!("28"), json!("100"), json!("baz")],
        );
    }

    #[test]
    fn test_unmarshal_yaml_text_unmarshaler_key() {
        let data = r##"{"#1#":"bar","#28#":true}"##;

        let om: OrderedMap<Marshallable, serde_json::Value> = serde_yaml::from_str(data).unwrap();

        assert_ordered_pairs_equal(&om, &[Marshallable(1), Marshallable(28)], &[json!("bar"), json!(true)]);
    }

    #[test]
    fn test_unmarshal_yaml_not_an_object() {
        for data in ["true", r#"["foo"]"#, "42", r#""foo""#] {
            let om = serde_yaml::from_str::<OrderedMap<i32, serde_json::Value>>(data);
            assert!(om.is_err(), "expected an error for {data}");
        }
    }

    #[test]
    fn test_unmarshal_yaml_empty_map() {
        let data = "{}";

        let om: OrderedMap<i32, serde_json::Value> = serde_yaml::from_str(data).unwrap();

        assert_len_equal(&om, 0);
    }

    #[test]
    fn test_yaml_special_characters() {
        let baseline_map =
            std::collections::BTreeMap::from([(SPECIAL_CHARACTERS.to_owned(), SPECIAL_CHARACTERS.to_owned())]);
        let baseline_data = serde_yaml::to_string(&baseline_map).unwrap();

        let mut om = OrderedMap::<String, serde_json::Value>::new();
        om.set(SPECIAL_CHARACTERS.to_owned(), json!(SPECIAL_CHARACTERS));
        let b = serde_yaml::to_string(&om).unwrap();
        assert_eq!(baseline_data, b);

        let mut om2 = OrderedMap::<MyString, MyString>::new();
        om2.set(MyString(SPECIAL_CHARACTERS.to_owned()), MyString(SPECIAL_CHARACTERS.to_owned()));
        let b = serde_yaml::to_string(&om2).unwrap();
        assert_eq!(baseline_data, b);

        let om: OrderedMap<String, serde_json::Value> = serde_yaml::from_str(&baseline_data).unwrap();
        assert_ordered_pairs_equal(&om, &key_strings([SPECIAL_CHARACTERS]), &[json!(SPECIAL_CHARACTERS)]);

        let om2: OrderedMap<MyString, MyString> = serde_yaml::from_str(&baseline_data).unwrap();
        assert_ordered_pairs_equal(
            &om2,
            &[MyString(SPECIAL_CHARACTERS.to_owned())],
            &[MyString(SPECIAL_CHARACTERS.to_owned())],
        );
    }

    #[test]
    fn test_yaml_round_trip() {
        // serde_yaml's emitter differs, so the round trip is checked structurally.
        let nested_input = "\
x: 28
m:
    bar:
        - 5:
            foo: bar
    foo:
        - 12:
            b: true
            i: 12
            m:
                a: b
                c: 28
            \"n\": null
          28:
            a: false
            b:
                - 1
                - 2
                - 3
        - 3:
            c: null
            d: 87
          4:
            e: true
          5:
            f: 4
            g: 5
            h: 6
";

        let target: NestedMaps = serde_yaml::from_str(nested_input).unwrap();
        let out = serde_yaml::to_string(&target).unwrap();

        let expected: serde_yaml::Value = serde_yaml::from_str(nested_input).unwrap();
        let actual: serde_yaml::Value = serde_yaml::from_str(&out).unwrap();
        assert_eq!(expected, actual);

        let target: OrderedMap<String, serde_json::Value> = serde_yaml::from_str("{}\n").unwrap();
        let out = serde_yaml::to_string(&target).unwrap();
        assert_eq!("{}\n", out);

        let special_input = "�: 0\n";
        let target: OrderedMap<String, i32> = serde_yaml::from_str(special_input).unwrap();
        let out = serde_yaml::to_string(&target).unwrap();
        assert_eq!(special_input, out);
    }

    #[test]
    fn test_round_trip_yaml_fuzz_corpus() {
        round_trip_yaml_maps::<String, String>();
        round_trip_yaml_maps::<String, i32>();
        round_trip_yaml_maps::<String, serde_json::Value>();
        round_trip_yaml_structs();
    }

    fn round_trip_yaml_maps<K, V>()
    where
        K: Eq + std::hash::Hash + Clone + DeserializeOwned + Serialize + Debug,
        V: DeserializeOwned + Serialize + PartialEq + Debug,
    {
        for data in YAML_CORPUS {
            let Ok(v1) = serde_yaml::from_str::<OrderedMap<K, V>>(data) else {
                continue;
            };

            let yaml_data = serde_yaml::to_string(&v1).unwrap();

            let v2: OrderedMap<K, V> = serde_yaml::from_str(&yaml_data).unwrap();

            assert!(assert_ordered_maps_equal(&v1, &v2), "failed with input data {data:?}");
        }
    }

    fn round_trip_yaml_structs() {
        for data in YAML_CORPUS {
            let Ok(v1) = serde_yaml::from_str::<TestFuzzStruct>(data) else {
                continue;
            };

            let yaml_data = serde_yaml::to_string(&v1).unwrap();

            let v2: TestFuzzStruct = serde_yaml::from_str(&yaml_data).unwrap();

            assert!(assert_test_fuzz_struct_equal(&v1, &v2), "failed with input data {data:?}");
        }
    }
}
