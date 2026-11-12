/// xoshiro256** with splitmix64 seeding; no dependencies.
pub struct Rng { s: [u64; 4] }
impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut z = seed;
        let mut s = [0u64; 4];
        for x in s.iter_mut() {
            z = z.wrapping_add(0x9E3779B97F4A7C15);
            let mut v = z;
            v = (v ^ (v >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            v = (v ^ (v >> 27)).wrapping_mul(0x94D049BB133111EB);
            *x = v ^ (v >> 31);
        }
        Rng { s }
    }
    pub fn u(&mut self) -> u64 {
        let r = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0]; self.s[3] ^= self.s[1]; self.s[1] ^= self.s[2]; self.s[0] ^= self.s[3];
        self.s[2] ^= t; self.s[3] = self.s[3].rotate_left(45);
        r
    }
    pub fn f(&mut self) -> f64 { (self.u() >> 11) as f64 / (1u64 << 53) as f64 }
    pub fn range(&mut self, a: f64, b: f64) -> f64 { a + (b - a) * self.f() }
    pub fn exp(&mut self, mean: f64) -> f64 { -mean * (1.0 - self.f()).ln() }
    pub fn normal(&mut self) -> f64 {
        let u1 = 1.0 - self.f(); let u2 = self.f();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
}
