use blstrs_plus::{G2Affine, Scalar};
use hex::ToHex;
use serde::{
    de::{self, MapAccess, Visitor},
    ser::SerializeStruct,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, marker::PhantomData};

#[derive(Debug, Clone)]
pub struct UavConfig {
    pub uid: String,
    pub sk: Scalar,
    pub pk: G2Affine,
}

impl UavConfig {
    pub fn new(uid: String, sk: Scalar, pk: G2Affine) -> Self {
        Self { uid, sk, pk }
    }
}

// #[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
// pub struct UavRuid {
//     pub ruid: String,
//     pub ip_addr: String,
// }

// impl UavRuid {
//     pub fn new(ruid: String, ip_addr: String) -> Self {
//         Self { ruid, ip_addr }
//     }
// }

impl Serialize for UavConfig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut st = serializer.serialize_struct("UavConfig", 3)?;
        st.serialize_field("uid", &self.uid)?;
        st.serialize_field("sk", &self.sk.to_be_bytes().encode_hex::<String>())?;
        st.serialize_field("pk", &self.pk.to_compressed().encode_hex::<String>())?;
        st.end()
    }
}

impl<'de> Deserialize<'de> for UavConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        enum Field {
            Uid,
            Sk,
            Pk,
        }

        // 告诉serde三种可能的 field 名
        struct FieldVisitor;
        impl<'de> Visitor<'de> for FieldVisitor {
            type Value = Field;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "`uid`, `sk` or `pk`")
            }
            fn visit_str<E>(self, value: &str) -> Result<Field, E>
            where
                E: de::Error,
            {
                match value {
                    "uid" => Ok(Field::Uid),
                    "sk" => Ok(Field::Sk),
                    "pk" => Ok(Field::Pk),
                    _ => Err(de::Error::unknown_field(value, &["uid", "sk", "pk"])),
                }
            }
        }

        impl<'de> Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Field, D::Error>
            where
                D: Deserializer<'de>,
            {
                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        // 真正的 Visitor，用来构造 UavConfig
        struct UavConfigVisitor {
            marker: PhantomData<fn() -> UavConfig>,
        }
        impl<'de> Visitor<'de> for UavConfigVisitor {
            type Value = UavConfig;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "struct UavConfig")
            }

            fn visit_map<V>(self, mut map: V) -> Result<UavConfig, V::Error>
            where
                V: MapAccess<'de>,
            {
                let mut uid: Option<String> = None;
                let mut sk: Option<Scalar> = None;
                let mut pk: Option<G2Affine> = None;

                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Uid => {
                            if uid.is_some() {
                                return Err(de::Error::duplicate_field("uid"));
                            }
                            uid = Some(map.next_value()?);
                        }
                        Field::Sk => {
                            if sk.is_some() {
                                return Err(de::Error::duplicate_field("sk"));
                            }
                            let hex_str: String = map.next_value()?;
                            let scalar_ctopt = Scalar::from_be_hex(&hex_str);
                            if scalar_ctopt.is_none().into() {
                                return Err(de::Error::custom(format!("sk hex decode error: {hex_str}")));
                            }
                            let scalar: Scalar = scalar_ctopt.unwrap();
                            sk = Some(scalar);
                        }
                        Field::Pk => {
                            if pk.is_some() {
                                return Err(de::Error::duplicate_field("pk"));
                            }
                            let hex_str: String = map.next_value()?;
                            let g2_ctopt = G2Affine::from_compressed_hex(&hex_str);
                            if g2_ctopt.is_none().into() {
                                return Err(de::Error::custom(format!("pk hex decode error: {hex_str}")));
                            }
                            let g2 = g2_ctopt.unwrap();
                            pk = Some(g2);
                        }
                    }
                }

                let uid = uid.ok_or_else(|| de::Error::missing_field("uid"))?;
                let sk = sk.ok_or_else(|| de::Error::missing_field("sk"))?;
                let pk = pk.ok_or_else(|| de::Error::missing_field("pk"))?;
                Ok(UavConfig { uid, sk, pk })
            }
        }

        const FIELDS: &[&str] = &["uid", "sk", "pk"];
        deserializer.deserialize_struct("UavConfig", FIELDS, UavConfigVisitor { marker: PhantomData })
    }
}
