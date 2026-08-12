pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774a, 0x34b0bcb5, 0x391c0c92, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

#[inline]
fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
#[inline]
fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
#[inline]
fn sigma0(x: u32) -> u32 { x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22) }
#[inline]
fn sigma1(x: u32) -> u32 { x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25) }
#[inline]
fn gamma0(x: u32) -> u32 { x.rotate_right(7) ^ x.rotate_right(18) ^ x.rotate_right(3) }
#[inline]
fn gamma1(x: u32) -> u32 { x.rotate_right(17) ^ x.rotate_right(19) ^ x.rotate_right(10) }

pub struct Sha256Compressor;

impl Sha256Compressor {
    fn message_schedule(&self, w0: [u32; 16]) -> [u32; 64] {
        let mut w = [0u32; 64];
        for i in 0..16 { w[i] = w0[i]; }
        for i in 16..64 {
            w[i] = gamma1(w[i-2]).wrapping_add(w[i-7]).wrapping_add(gamma0(w[i-15])).wrapping_add(w[i-16]);
        }
        w
    }

    pub fn compress_n_rounds(&self, state: [u32; 8], message_block: [u32; 16], rounds: usize) -> [u32; 8] {
        let w = self.message_schedule(message_block);
        let mut a = state[0];
        let mut b = state[1];
        let mut c = state[2];
        let mut d = state[3];
        let mut e = state[4];
        let mut f = state[5];
        let mut g = state[6];
        let mut h = state[7];
        let r = rounds.min(64);
        for i in 0..r {
            let t1 = h.wrapping_add(sigma1(e)).wrapping_add(ch(e,f,g)).wrapping_add(K[i]).wrapping_add(w[i]);
            let t2 = sigma0(a).wrapping_add(maj(a,b,c));
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        [
            state[0].wrapping_add(a),
            state[1].wrapping_add(b),
            state[2].wrapping_add(c),
            state[3].wrapping_add(d),
            state[4].wrapping_add(e),
            state[5].wrapping_add(f),
            state[6].wrapping_add(g),
            state[7].wrapping_add(h),
        ]
    }

    pub fn compress(&self, state: [u32; 8], message_block: [u32; 16]) -> [u32; 8] {
        self.compress_n_rounds(state, message_block, 64)
    }

    pub fn diff_propagation(&self, delta_state: [u32;8], delta_block: [u32;16], rounds: usize) -> [u32;8] {
        let s0 = self.compress_n_rounds([0u32;8], [0u32;16], rounds);
        let s1 = self.compress_n_rounds(delta_state, delta_block, rounds);
        let mut out = [0u32;8];
        for i in 0..8 { out[i] = s0[i] ^ s1[i]; }
        out
    }

    pub fn active_words(state: &[u32;8]) -> usize {
        state.iter().filter(|&&v| v != 0).count()
    }
}
