pub const RC: [u64; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

const ROT: [[u32;5];5] = [
    [0,36,3,41,18],
    [1,44,10,45,2],
    [62,6,43,15,61],
    [28,55,25,21,56],
    [27,20,39,8,14],
];

type State = [[u64;5];5];

pub struct KeccakF;

impl KeccakF {
    pub fn new() -> Self { Self }

    fn theta(&self, a: &mut State) {
        let mut c = [0u64;5];
        for x in 0..5 {
            c[x] = a[x][0] ^ a[x][1] ^ a[x][2] ^ a[x][3] ^ a[x][4];
        }
        let mut d = [0u64;5];
        for x in 0..5 {
            d[x] = c[(x+4)%5] ^ c[(x+1)%5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x][y] ^= d[x];
            }
        }
    }

    fn rho(&self, a: &mut State) {
        for x in 0..5 {
            for y in 0..5 {
                let r = ROT[x][y] as u32;
                a[x][y] = a[x][y].rotate_left(r);
            }
        }
    }

    fn pi(&self, a: &mut State) {
        let mut b = [[0u64;5];5];
        for x in 0..5 {
            for y in 0..5 {
                b[y][(2*x+3*y)%5] = a[x][y];
            }
        }
        *a = b;
    }

    fn chi(&self, a: &mut State) {
        let mut b = [[0u64;5];5];
        for x in 0..5 {
            for y in 0..5 {
                b[x][y] = a[x][y] ^ (!a[(x+1)%5][y] & a[(x+2)%5][y]);
            }
        }
        *a = b;
    }

    fn iota(&self, a: &mut State, round: usize) {
        a[0][0] ^= RC[round];
    }

    pub fn apply_round(&self, a: &mut State, round: usize) {
        self.theta(a);
        self.rho(a);
        self.pi(a);
        self.chi(a);
        self.iota(a, round);
    }

    pub fn permute(&self, mut a: State, rounds: usize) -> State {
        for r in 0..rounds {
            self.apply_round(&mut a, r);
        }
        a
    }

    pub fn diff_propagation(&self, delta: State, rounds: usize) -> State {
        let s0 = [[0u64;5];5];
        let s1 = delta;
        let s0 = self.permute(s0, rounds);
        let s1 = self.permute(s1, rounds);
        let mut out = [[0u64;5];5];
        for x in 0..5 {
            for y in 0..5 {
                out[x][y] = s0[x][y] ^ s1[x][y];
            }
        }
        out
    }

    pub fn active_lanes(state: &State) -> usize {
        let mut cnt = 0;
        for x in 0..5 {
            for y in 0..5 {
                if state[x][y] != 0 { cnt += 1; }
            }
        }
        cnt
    }

    fn chi_bit_prob(dx: u8, dy: u8, dz: u8) -> f64 {
        if dx == 0 && dy == 0 && dz == 0 {
            1.0
        } else if dx == 1 && dy == 0 && dz == 0 {
            0.0
        } else {
            0.5
        }
    }

    pub fn chi_ddt_probability(state_diff: &State) -> f64 {
        let mut prob = 1.0;
        for x in 0..5 {
            for y in 0..5 {
                let a = state_diff[x][y];
                let b = state_diff[(x+1)%5][y];
                let c = state_diff[(x+2)%5][y];
                for bit in 0..64 {
                    let dx = ((a >> bit) & 1) as u8;
                    let dy = ((b >> bit) & 1) as u8;
                    let dz = ((c >> bit) & 1) as u8;
                    let p = Self::chi_bit_prob(dx, dy, dz);
                    if p == 0.0 {
                        return 0.0;
                    }
                    prob *= p;
                    if prob == 0.0 {
                        return 0.0;
                    }
                }
            }
        }
        prob
    }
}
