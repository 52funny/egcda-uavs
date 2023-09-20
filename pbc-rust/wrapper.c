#include "wrapper.h"

#include <gmp.h>
#include <stdio.h>

/// Pairing applying
// pairing
void element_pairing__extern(element_t out, element_t in1, element_t in2) {
  element_pairing(out, in1, in2);
}
void pairing_apply__extern(element_t out, element_t in1, element_t in2,
                           pairing_t pairing) {
  pairing_apply(out, in1, in2, pairing);
}

// prod pairing
void element_prod_pairing__extern(element_t out, element_t in1[],
                                  element_t in2[], int n) {
  element_prod_pairing(out, in1, in2, n);
}

// is_symmetric
int pairing_is_symmetric__extern(pairing_t pairing) {
  return pairing_is_symmetric(pairing);
}

/// Initializing elements
// init g1
void element_init_G1__extern(element_t e, pairing_t pairing) {
  element_init_G1(e, pairing);
}
// init g2
void element_init_G2__extern(element_t e, pairing_t pairing) {
  element_init_G2(e, pairing);
}
// init gt
void element_init_GT__extern(element_t e, pairing_t pairing) {
  element_init(e, pairing->GT);
  // element_init_GT(e, pairing);
}
// init zr
void element_init_Zr__extern(element_t e, pairing_t pairing) {
  element_init_Zr(e, pairing);
}
// init same as
void element_init_same_as__extern(element_t e, element_t e2) {
  element_init_same_as(e, e2);
}

// clear
void element_clear__extern(element_t e) { element_clear(e); }

//
// Element assigning operator
//
// set 0
void element_set0__extern(element_t e) { element_set0(e); }
// set 1
void element_set1__extern(element_t e) { element_set1(e); }
// set i
void element_set_si__extern(element_t e, long i) { element_set_si(e, i); }
// set e to a
void element_set__extern(element_t e, element_t a) { element_set(e, a); }

//
// Element converting operator
//
// from hash
void element_from_hash__extern(element_t e, void* data, int len) {
  element_from_hash(e, data, len);
}

//
// Element arithmetic operator
//
// add
void element_add__extern(element_t n, element_t a, element_t b) {
  element_add(n, a, b);
}
// sub
void element_sub__extern(element_t n, element_t a, element_t b) {
  element_sub(n, a, b);
}
// mul
void element_mul__extern(element_t n, element_t a, element_t b) {
  element_mul(n, a, b);
}
// mul si
void element_mul_si__extern(element_t n, element_t a, long z) {
  element_mul_si(n, a, z);
}
// mul zn
void element_mul_zn__extern(element_t n, element_t a, element_t z) {
  element_mul_zn(n, a, z);
}
// div
void element_div__extern(element_t n, element_t a, element_t b) {
  element_div(n, a, b);
}
// invert
void element_invert__extern(element_t n, element_t a) { element_invert(n, a); }

// pow
void element_pow_zn__extern(element_t x, element_t a, element_t n) {
  element_pow_zn(x, a, n);
}
//
// Element comparing
//
int element_cmp__extern(element_t a, element_t b) { return element_cmp(a, b); }

//
// Element random assigning operator
//
// random
void element_random__extern(element_t e) { element_random(e); }

//
// element export/import operator
//
// element to bytes
int element_to_bytes__extern(unsigned char* data, element_t e) {
  return element_to_bytes(data, e);
}

// bytes to element
int element_from_bytes__extern(element_t e, unsigned char* data) {
  return element_from_bytes(e, data);
}

// compressed bytes to element
int element_from_bytes_compressed__extern(element_t e, unsigned char* data) {
  return element_from_bytes_compressed(e, data);
};

// element length in bytes
int element_length_in_bytes__extern(element_t e) {
  return element_length_in_bytes(e);
}

// element length in compressed bytes
int element_length_in_bytes_compressed__extern(element_t e) {
  return element_length_in_bytes_compressed(e);
}
