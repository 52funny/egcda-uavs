use std::ffi::CString;

use crate::{
    bindings::{
        element_init_G1, element_init_G2, element_init_GT, element_init_Zr, element_pairing,
        element_prod_pairing, element_s, pairing_apply, pairing_clear, pairing_init_set_buf,
        pairing_init_set_str, pairing_is_symmetric, pairing_s,
    },
    pairing_t, Element,
};

#[derive(Debug)]
pub struct Pairing {
    pairing: pairing_t,
}

unsafe impl Send for Pairing {}
unsafe impl Sync for Pairing {}

impl Default for Pairing {
    fn default() -> Self {
        Self {
            pairing: unsafe { [std::mem::zeroed::<pairing_s>(); 1] },
        }
    }
}
impl Pairing {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn new(str: &str) -> Self {
        let mut pairing = Pairing::empty();
        pairing.init_from_str(str);
        pairing
    }

    pub fn init_from_buf(&mut self, buf: impl AsRef<[u8]>) {
        let buf = buf.as_ref();
        unsafe { pairing_init_set_buf(self.pairing.as_mut_ptr(), buf.as_ptr().cast(), buf.len()) };
    }

    pub fn init_from_str(&mut self, str: &str) {
        unsafe {
            let c_string = CString::from_vec_unchecked(str.as_bytes().to_vec());
            // let c_str = c_string.as;
            pairing_init_set_str(self.pairing.as_mut_ptr(), c_string.as_ptr());
        }
    }

    pub fn element_pairing(&self, g1: &Element, g2: &Element) -> Element {
        let mut gt = self.gt();
        unsafe {
            element_pairing(
                gt.element.as_mut_ptr().cast(),
                g1.element.as_ptr() as *mut element_s,
                g2.element.as_ptr() as *mut element_s,
            )
        };
        gt
    }
    pub fn element_prod_pairing(
        &self,
        g1: impl AsRef<[Element]>,
        g2: impl AsRef<[Element]>,
    ) -> Element {
        let mut g1: Vec<_> = g1.as_ref().iter().map(|x| x.element).collect();
        let mut g2: Vec<_> = g2.as_ref().iter().map(|x| x.element).collect();
        let mut gt = self.gt();
        unsafe {
            element_prod_pairing(
                gt.element.as_mut_ptr().cast(),
                g1.as_mut_ptr(),
                g2.as_mut_ptr(),
                g1.len() as i32,
            )
        };
        gt
    }

    pub fn is_symmetric(&self) -> bool {
        (unsafe { pairing_is_symmetric(self.pairing.as_ptr() as *mut pairing_s) }) == 1
    }

    // Initalize g1
    pub fn g1(&self) -> Element {
        let mut e = Element::new_from_pairing();
        unsafe {
            element_init_G1(
                e.element.as_mut_ptr().cast(),
                self.pairing.as_ptr() as *mut pairing_s,
            )
        }
        e
    }
    // Initalize g2
    pub fn g2(&self) -> Element {
        let mut e = Element::new_from_pairing();
        unsafe {
            element_init_G2(
                e.element.as_mut_ptr().cast(),
                self.pairing.as_ptr() as *mut pairing_s,
            )
        }
        e
    }
    // Initalize gt
    pub fn gt(&self) -> Element {
        let element = unsafe { [std::mem::zeroed(); 1] };
        let mut e = Element { element };
        unsafe {
            element_init_GT(
                e.element.as_mut_ptr().cast(),
                self.pairing.as_ptr() as *mut pairing_s,
            )
        }
        e
    }

    // Initalize gr
    pub fn gr(&self) -> Element {
        let mut e = Element::new_from_pairing();
        unsafe {
            element_init_Zr(
                e.element.as_mut_ptr().cast(),
                self.pairing.as_ptr() as *mut pairing_s,
            )
        }
        e
    }

    // pairing
    pub fn pairing(&self, e1: &Element, e2: &Element) -> Element {
        let mut gt = self.gt();
        unsafe {
            pairing_apply(
                gt.element.as_mut_ptr().cast(),
                e1.element.as_ptr() as *mut element_s,
                e2.element.as_ptr() as *mut element_s,
                self.pairing.as_ptr() as *mut pairing_s,
            );
        }
        gt
    }
}

// manual drop pairing
impl Drop for Pairing {
    fn drop(&mut self) {
        unsafe {
            pairing_clear(self.pairing.as_mut_ptr().cast());
        }
    }
}

#[cfg(test)]
mod test {
    use super::Pairing;
    const INIT_TEXT_FR256: &str = "type f
    q 115792089237314936872688561244471742058375878355761205198700409522629664518163
    r 115792089237314936872688561244471742058035595988840268584488757999429535617037
    b 3
    beta 76600213043964638334639432839350561620586998450651561245322304548751832163977
    alpha0 82889197335545133675228720470117632986673257748779594473736828145653330099944
    alpha1 66367173116409392252217737940259038242793962715127129791931788032832987594232";

    #[test]
    fn test_element_pairing() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);
        assert!(!p.is_symmetric())
    }
    #[test]
    fn test_bls_sig() {
        let mut p = Pairing::empty();
        p.init_from_str(INIT_TEXT_FR256);

        let secret_key = p.gr().random();
        let h = p.g1().from_hash("ABCDEF");
        let g = p.g2().random();

        let mut public_key = g.clone();
        public_key.pow_zn(&secret_key);

        let mut sig = h.clone();
        sig.pow_zn(&secret_key);

        let out1 = p.pairing(&h, &public_key);
        let out2 = p.pairing(&sig, &g);

        assert_eq!(out1, out2);
    }
}
