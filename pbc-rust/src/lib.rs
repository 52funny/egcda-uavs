#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(improper_ctypes)]
#![allow(dead_code)]

use core::panic;
use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign},
};

use self::bindings::{
    element_cmp, element_mul_zn, element_set0, element_set1, element_t, pairing_t,
};
use crate::bindings::{element_length_in_bytes, element_random, element_to_bytes};
use bindings::{
    element_add, element_clear, element_div, element_from_bytes, element_from_bytes_compressed,
    element_from_hash, element_init_same_as, element_invert, element_length_in_bytes_compressed,
    element_mul, element_mul_si, element_pow_zn, element_s, element_set, element_set_si,
    element_sub, element_to_bytes_compressed,
};
// use pairing::Pairing;
pub(crate) mod bindings;
// include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub(crate) mod pairing;
pub use pairing::Pairing;

pub const INIT_TEXT_FR256: &str = "type f
    q 115792089237314936872688561244471742058375878355761205198700409522629664518163
    r 115792089237314936872688561244471742058035595988840268584488757999429535617037
    b 3
    beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
    alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
    alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232
";

pub struct Element {
    element: element_t,
    // pairing_ptr: *mut Pairing,
}

unsafe impl Send for Element {}
unsafe impl Sync for Element {}

impl Debug for Element {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let bytes = hex::encode(self.as_bytes());
        f.debug_struct("Element").field("bytes", &bytes).finish()
    }
}

impl Element {
    pub(crate) fn new_from_pairing() -> Self {
        let element = unsafe { [std::mem::zeroed(); 1] };
        Self { element }
    }
    pub fn set1(mut self) -> Self {
        unsafe { element_set1(self.element.as_mut_ptr().cast()) };
        self
    }
    pub fn set0(mut self) -> Self {
        unsafe { element_set0(self.element.as_mut_ptr().cast()) };
        self
    }
    pub fn set_i(mut self, i: i64) -> Self {
        unsafe { element_set_si(self.element.as_mut_ptr().cast(), i) }
        self
    }
    // pub fn from_bytes(mut self, data: impl AsRef<[u8]>) -> Self {}

    pub fn from_hash(mut self, data: impl AsRef<[u8]>) -> Self {
        let data = data.as_ref();
        unsafe {
            element_from_hash(
                self.element.as_mut_ptr(),
                std::mem::transmute(data.as_ptr()),
                data.len() as i32,
            )
        }
        self
    }

    // arithmetic
    pub fn add_element(&mut self, e: Self) {
        let mut e = e;
        let mut self_copy = self.clone();
        unsafe {
            element_add(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                e.element.as_mut_ptr().cast(),
            )
        }
    }
    pub fn sub_element(&mut self, e: Self) {
        let mut e = e;
        let mut self_copy = self.clone();
        unsafe {
            element_sub(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                e.element.as_mut_ptr().cast(),
            )
        }
    }
    pub fn mul_element(&mut self, e: Self) {
        let mut e = e;
        let mut self_copy = self.clone();
        unsafe {
            element_mul(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                e.element.as_mut_ptr().cast(),
            )
        }
    }
    pub fn mul_element_zn(&mut self, e: Self) {
        let mut e = e;
        let mut self_copy = self.clone();
        unsafe {
            element_mul_zn(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                e.element.as_mut_ptr().cast(),
            )
        }
    }
    pub fn mul_element_i(&mut self, i: i64) {
        let mut self_copy = self.clone();
        unsafe {
            element_mul_si(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                i,
            )
        }
    }

    pub fn div_element(&mut self, e: Self) {
        let mut e = e;
        let mut self_copy = self.clone();
        unsafe {
            element_div(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                e.element.as_mut_ptr().cast(),
            )
        }
    }
    pub fn invert(&mut self) -> Self {
        let mut self_copy = self.clone();
        unsafe {
            element_invert(
                self_copy.element.as_mut_ptr().cast(),
                self.element.as_mut_ptr().cast(),
            )
        }
        self_copy
    }

    pub fn pow_zn(&mut self, e: &Self) {
        let mut self_copy = self.clone();
        unsafe {
            element_pow_zn(
                self.element.as_mut_ptr().cast(),
                self_copy.element.as_mut_ptr().cast(),
                e.element.as_ptr() as *mut element_s,
            )
        }
    }
    // random
    pub fn random(mut self) -> Self {
        unsafe { element_random(self.element.as_mut_ptr().cast()) };
        self
    }

    // export/import
    pub fn bytes_len(&self) -> usize {
        unsafe { element_length_in_bytes(self.element.as_ptr() as *mut element_s) as usize }
    }

    pub fn bytes_compressed_len(&self) -> usize {
        unsafe {
            element_length_in_bytes_compressed(self.element.as_ptr() as *mut element_s) as usize
        }
    }
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.bytes_len()];
        let written =
            unsafe { element_to_bytes(v.as_mut_ptr(), self.element.as_ptr() as *mut element_s) };
        if written as usize != v.len() {
            panic!("write size not equal buf size")
        }
        v
    }

    // must data length equals bytes_len
    pub fn from_bytes(&mut self, data: impl AsRef<[u8]>) -> usize {
        unsafe {
            element_from_bytes(
                self.element.as_mut_ptr(),
                std::mem::transmute(data.as_ref().as_ptr()),
            ) as usize
        }
    }

    pub fn as_bytes_compressed(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.bytes_compressed_len()];
        let written = unsafe {
            element_to_bytes_compressed(v.as_mut_ptr(), self.element.as_ptr() as *mut element_s)
        };
        if written as usize != v.len() {
            panic!("write size not equal buf size")
        }
        v
    }
    // must data length equals bytes_compressed_len
    pub fn from_bytes_compressed(&mut self, data: impl AsRef<[u8]>) -> usize {
        unsafe {
            element_from_bytes_compressed(
                self.element.as_mut_ptr(),
                std::mem::transmute(data.as_ref().as_ptr()),
            ) as usize
        }
    }
}

impl Clone for Element {
    fn clone(&self) -> Self {
        let mut e: element_t = unsafe { std::mem::zeroed() };
        unsafe {
            element_init_same_as(
                e.as_mut_ptr().cast(),
                self.element.as_ptr() as *mut element_s,
            );
            element_set(
                e.as_mut_ptr().cast(),
                self.element.as_ptr() as *mut element_s,
            );
        }
        Self {
            element: e,
            // pairing_ptr: self.pairing_ptr,
        }
    }
}

impl Drop for Element {
    fn drop(&mut self) {
        unsafe { element_clear(self.element.as_mut_ptr().cast()) }
    }
}

impl PartialEq for Element {
    fn eq(&self, other: &Self) -> bool {
        unsafe {
            element_cmp(
                self.element.as_ptr() as *mut element_s,
                other.element.as_ptr() as *mut element_s,
            ) == 0
        }
    }
}

impl PartialOrd for Element {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        let res = unsafe {
            element_cmp(
                self.element.as_ptr() as *mut element_s,
                other.element.as_ptr() as *mut element_s,
            )
        };
        match res {
            0 => Some(std::cmp::Ordering::Equal),
            1 => Some(std::cmp::Ordering::Greater),
            -1 => Some(std::cmp::Ordering::Less),
            _ => unreachable!(),
        }
    }
}

impl Add for Element {
    type Output = Self;
    fn add(self, rhs: Self) -> Self::Output {
        let mut copy = self.clone();
        copy.add_element(rhs);
        copy
    }
}

impl AddAssign for Element {
    fn add_assign(&mut self, rhs: Self) {
        self.add_element(rhs)
    }
}

impl Sub for Element {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self::Output {
        let mut copy = self.clone();
        copy.sub_element(rhs);
        copy
    }
}

impl SubAssign for Element {
    fn sub_assign(&mut self, rhs: Self) {
        self.sub_element(rhs)
    }
}

impl Mul for Element {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self::Output {
        let mut copy = self.clone();
        copy.mul_element(rhs);
        copy
    }
}
impl MulAssign for Element {
    fn mul_assign(&mut self, rhs: Self) {
        self.mul_element(rhs)
    }
}

impl Div for Element {
    type Output = Self;
    fn div(self, rhs: Self) -> Self::Output {
        let mut copy = self.clone();
        copy.div_element(rhs);
        copy
    }
}
impl DivAssign for Element {
    fn div_assign(&mut self, rhs: Self) {
        self.div_element(rhs)
    }
}

#[cfg(test)]
mod tests {
    use crate::pairing::Pairing;
    const INIT_TEXT_FR256: &str = "type f
q 115792089237314936872688561244471742058375878355761205198700409522629664518163
r 115792089237314936872688561244471742058035595988840268584488757999429535617037
b 3
beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";

    #[test]
    fn test_from_hash() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let p = p.g1().from_hash("ABCDEF");
        let result = "4142434445460041424344454601414243444546024142434445460341424344621df532eafbc819db10810e4bb62f740807be1baeed9be9eddab30f691aabd7";
        assert_eq!(result, hex::encode(p.as_bytes()));
    }
    #[test]
    fn test_from_bytes() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.g1();
        let r = [0u8; 64];
        g1.from_bytes(r);
        assert_eq!(r.to_vec(), g1.as_bytes());
    }
    #[test]
    fn set_0() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let g1 = p.g1().set1();
        let g2 = p.g2().set1();
        println!("{:x?}", g1.as_bytes());
        println!("{:x?}", g2.as_bytes());
    }
    #[test]
    fn test_add() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.gr().set_i(0x10);
        let g2 = p.gr().set_i(0xf);
        g1.add_element(g2);
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0x1f
            ],
            g1.as_bytes()
        );
    }
    #[test]
    fn test_mul() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.gr().set_i(0xff);
        let g2 = p.gr().set_i(0xf);
        g1.mul_element(g2);
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0x0e, 0xf1
            ],
            g1.as_bytes()
        );
        g1.mul_element_i(16);
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0xef, 0x10
            ],
            g1.as_bytes()
        );
    }
    #[test]
    fn test_div() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.gr().set_i(0xff);
        let g2 = p.gr().set_i(0xf);
        g1.div_element(g2);
        assert_eq!(
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0x11
            ],
            g1.as_bytes()
        );
    }
    #[test]
    fn test_equation() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.g1().from_hash("ABCsdfkjasdflkasjdfsdjflkasjflaksjdflaskjdflaskjdflkasjdflkajdflkajsdflkasjdflkjaslkdfjaslkdjfalskfjdlaskdfjlkasjdflkajsdlfkjasdflkjasldfkjasldkfjasldkfjasldkfj");
        let mut g2 = p.g2().from_hash("DEF");

        let res = g1.as_bytes();
        let a = p.gr().random();
        g2.mul_element(a);
        g1.sub_element(g2.clone());
        g1.add_element(g2);
        assert_eq!(res, g1.as_bytes())
    }
    #[test]
    fn test_invert() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.gr().set_i(17);
        let inv = g1.invert();
        assert_eq!(
            "3c3c3c3c3c3b83f410ae9361a18426bbc6ca7259318d8bca1bce6dfb7c7b21e5",
            hex::encode(inv.as_bytes())
        );
    }
    #[test]
    fn test_pow_zn() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.gr().random();
        let pow = p.gr().set_i(2);

        println!("g1 : {}", hex::encode(g1.as_bytes()));
        println!("pow: {}", hex::encode(pow.as_bytes()));
        g1.pow_zn(&pow);
        println!("g1 : {}", hex::encode(g1.as_bytes()));
    }
    #[test]
    fn test_eq() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let g1 = p.gr().random();
        let g2 = g1.clone();
        assert!(g1 == g2);
    }
    #[test]
    fn test_arithmetic() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        let mut g1 = p.gr().set_i(10);
        let g2 = p.gr().set_i(2);
        let res = p.gr().set_i(5);
        g1 /= g2;
        assert_eq!(res, g1);

        let g1 = p.gr().set_i(12);
        let g2 = p.gr().set_i(3);
        let res = p.gr().set_i(36);
        assert_eq!(res, g1 * g2);
    }
    #[test]
    fn test_cmp() {
        let mut p = Pairing::empty();
        p.init_from_buf(INIT_TEXT_FR256);
        let g1 = p.gr().set_i(10);
        let g2 = p.gr().set_i(11);
        assert!(g1 < g2);
    }
    #[test]
    fn test_it() {
        let mut p = Pairing::new("type a
        q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791
        h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776
        r 730750818665451621361119245571504901405976559617
        exp2 159
        exp1 107
        sign1 1
        sign0 1
        ");
        let g1 = p.g1().random();
        println!("{:?}", g1);
    }
}
