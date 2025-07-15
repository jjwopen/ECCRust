// 암호화·복호화에 필요한 상수, 함수, 구조체 등 정의
use std::fs;
use std::io;
use num_bigint::BigUint;
use num_traits::Num;
use lazy_static::lazy_static;
use rand::{rngs::OsRng, TryRngCore};


// const KEY_SIZE: usize = 32; // 대칭키 크기
pub const BLOCK_SIZE: usize = 16; // AES Block 크기

// ---
// 1. FieldElement 구조체 및 연산 구현
// ---

// 유한체 내 값과 p로 사용할 소수 구조 정의
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldElement {
    pub value: BigUint,
    pub modulus: BigUint,
}

// 유한체 내 함수 및 메소드 정의
impl FieldElement {
    // 모듈러 연산 함수
    pub fn new(value: BigUint, modulus: BigUint) -> Self {
        Self { value: value % &modulus, modulus }
    }

    // 다음 메소드들은 유한체 내에서의 사칙연산을 위해 새롭게 정의되는 메소드임.
    // 덧셈 메소드
    pub fn add(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Moduli must match for addition");
        Self::new(&self.value + &other.value, self.modulus.clone())
    }

    // 뺄셈 메소드
    pub fn sub(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Moduli must match for subtraction");
        let mut result = &self.value + &self.modulus; // 음수 방지
        result = &result - &other.value;
        Self::new(result, self.modulus.clone())
    }

    // 곱셈 메소드
    pub fn mul(&self, other: &Self) -> Self {
        assert_eq!(self.modulus, other.modulus, "Moduli must match for multiplication");
        Self::new(&self.value * &other.value, self.modulus.clone())
    }

    // 모듈러 역원 메소드
    pub fn inverse(&self) -> Option<Self> {
        if self.value == BigUint::from(0u8) {
            return None; // 0은 역원이 없음
        }
        let p_minus_2 = &self.modulus - BigUint::from(2u8);
        Some(Self::new(self.value.modpow(&p_minus_2, &self.modulus), self.modulus.clone()))
    }

    // 나눗셈 메소드
    pub fn div(&self, other: &Self) -> Option<Self> {
        if let Some(other_inverse) = other.inverse() {
            Some(self.mul(&other_inverse))
        } else {
            None // 0으로 나누려고 함
        }
    }
}

// ---
// 2. Point 구조체 및 EllipticCurve 구조체 정의
// ---

// 타원 곡선 위 점의 좌표와 무한원점(점 덧셈의 항등원) 구조 정의
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Coordinates { x: FieldElement, y: FieldElement },
    Identity, // 무한원점 O (Point at Infinity)
}

// 타원 곡선의 매개변수 구조 정의
#[derive(Debug, Clone)]
pub struct EllipticCurve {
    pub p: BigUint, // 유한체의 modulus (소수)
    pub a: FieldElement, // 곡선 계수 A
    // pub b: FieldElement, // 곡선 계수 B
    pub g: Point, // 기준점 G
    pub n: BigUint, // G의 위수 (Order), 즉 nG가 무한원점이 되는 n의 최소 정수
}

// ---
// 3. EllipticCurve의 연산 구현 (add_points, scalar_multiply)
// ---

// 타원 곡선 관련 메소드 정의
impl EllipticCurve {
    // 타원 곡선 위에 점이 존재하는지 확인하는 메소드
    // pub fn is_on_curve(&self, point: &Point) -> bool {
    //     match point {
    //         Point::Identity => true, // 무한원점은 항상 곡선 위에 있다고 간주
    //         Point::Coordinates { x, y } => {
    //             let y_squared = y.mul(y);
    //             let x_cubed = x.mul(x).mul(x);
    //             let ax = self.a.mul(x);
    //             let rhs = x_cubed.add(&ax).add(&self.b);
    //             y_squared == rhs
    //         }
    //     }
    // }

    // 점 덧셈 메소드
    pub fn add_points(&self, p: &Point, q: &Point) -> Point {
        match (p, q) {
            (Point::Identity, _) => q.clone(),
            (_, Point::Identity) => p.clone(),

            (Point::Coordinates { x: px, y: py }, Point::Coordinates { x: qx, y: qy })
            if px == qx && py != qy => Point::Identity, // P + (-P) = O

            (Point::Coordinates { x: px, y: py }, Point::Coordinates { x: qx, y: qy })
            if px == qx && py == qy => { // P = Q (2P)
                if py.value == BigUint::from(0u8) {
                    return Point::Identity;
                }

                let three_x_sq = FieldElement::new(BigUint::from(3u8), self.p.clone())
                    .mul(&px.mul(px));
                let numerator = three_x_sq.add(&self.a);
                let two_y = FieldElement::new(BigUint::from(2u8), self.p.clone())
                    .mul(py);
                let slope = numerator.div(&two_y).expect("Inverse of 2y failed in 2P calculation");

                let x3 = slope.mul(&slope).sub(&px).sub(&px);
                let y3 = slope.mul(&px.sub(&x3)).sub(py);
                Point::Coordinates { x: x3, y: y3 }
            },

            (Point::Coordinates { x: px, y: py }, Point::Coordinates { x: qx, y: qy }) => { // P != Q
                let numerator = qy.sub(py);
                let denominator = qx.sub(px);
                let slope = numerator.div(&denominator).expect("Inverse of (x2-x1) failed in P+Q calculation");

                let x3 = slope.mul(&slope).sub(px).sub(qx);
                let y3 = slope.mul(&px.sub(&x3)).sub(py);
                Point::Coordinates { x: x3, y: y3 }
            },
        }
    }

    // 스칼라 곱셈 메소드, Double-and-Add Algorithm
    pub fn scalar_multiply(&self, k: &BigUint, p: &Point) -> Point {
        let mut result = Point::Identity;
        let mut add_point = p.clone();
        let mut k_val = k.clone();

        while k_val > BigUint::from(0u8) {
            if &k_val % BigUint::from(2u8) == BigUint::from(1u8) {
                result = self.add_points(&result, &add_point);
            }
            add_point = self.add_points(&add_point, &add_point);
            k_val /= BigUint::from(2u8);
        }
        result
    }

    pub fn generate_private_key(&self) -> BigUint {
        let mut rng = OsRng;
        let mut private_key_bytes = vec![0u8; ((self.n.bits() + 7) / 8) as usize]; // n의 비트 길이에 맞게 바이트 배열 생성
        let private_key;
        loop {
            rng.try_fill_bytes(&mut private_key_bytes).unwrap();
            let candidate_key = BigUint::from_bytes_be(&private_key_bytes);
            if candidate_key > BigUint::from(0u8) && candidate_key < self.n {
                private_key = candidate_key;
                break;
            }
        }
        private_key
    }

    pub fn generate_public_key(&self, pk: &BigUint) -> Point {
        self.scalar_multiply(pk, &self.g)
    }

    // 공유 비밀점 생성 메소드
    pub fn ecdh_derive_shared_secret(&self, private_key: &BigUint, other_public_key: &Point) -> Vec<u8> {
        let shared_secret = self.scalar_multiply(private_key, other_public_key);
        match shared_secret {
            Point::Coordinates {x,y:_} => {
                x.value.to_bytes_be()
            }
            Point::Identity => {
                vec![0u8; 32]
            }
        }
    }
}

// ---
// 4. lazy_static! 매크로를 사용하여 ECC 파라미터 전역 상수 정의(Secp256k1)
// ---

lazy_static! {
    // p (유한체 모듈러스)
    pub static ref P_MODULUS_STR: &'static str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
    pub static ref P_MODULUS: BigUint = <BigUint as Num>::from_str_radix(*P_MODULUS_STR, 16)
        .expect("Failed to parse P_MODULUS_STR");

    // A (곡선 계수 A)
    pub static ref A_VALUE: BigUint = BigUint::from(0u8);
    pub static ref A_FIELD_ELEMENT: FieldElement = FieldElement::new(
        A_VALUE.clone(), P_MODULUS.clone()
    );

    // B (곡선 계수 B)
    // pub static ref B_VALUE: BigUint = BigUint::from(7u8);
    // pub static ref B_FIELD_ELEMENT: FieldElement = FieldElement::new(
    //     B_VALUE.clone(), P_MODULUS.clone()
    // );

    // Gx (기준점 G의 X좌표)
    pub static ref GX_STR: &'static str = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
    pub static ref GX_FIELD_ELEMENT: FieldElement = FieldElement::new(
        BigUint::from_str_radix(*GX_STR, 16)
            .expect("Failed to parse GX_STR"),
        P_MODULUS.clone()
    );

    // Gy (기준점 G의 Y좌표)
    pub static ref GY_STR: &'static str = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
    pub static ref GY_FIELD_ELEMENT: FieldElement = FieldElement::new(
        BigUint::from_str_radix(*GY_STR, 16)
            .expect("Failed to parse GY_STR"),
        P_MODULUS.clone()
    );

    // G_POINT (기준점 G)
    pub static ref G_POINT: Point = Point::Coordinates {
        x: GX_FIELD_ELEMENT.clone(),
        y: GY_FIELD_ELEMENT.clone(),
    };

    // n (G의 위수)
    pub static ref N_ORDER_STR: &'static str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    pub static ref N_ORDER: BigUint = BigUint::from_str_radix(*N_ORDER_STR, 16)
        .expect("Failed to parse N_ORDER_STR");

    // SECP256K1_CURVE (타원곡선 인스턴스)
    // 이 인스턴스를 통해 모든 ECC 연산 메소드에 접근합니다.
    pub static ref SECP256K1_CURVE: EllipticCurve = EllipticCurve {
        p: P_MODULUS.clone(),
        a: A_FIELD_ELEMENT.clone(),
        // b: B_FIELD_ELEMENT.clone(),
        g: G_POINT.clone(),
        n: N_ORDER.clone(),
    };
}


// 파일을 읽어 그 내용의 바이트값을 반환함.
pub fn read_file_to_bytes_sync(path: &str) -> Result<Vec<u8>, io::Error> {
    fs::read(path)
}

// path에 data(byte)를 씀.
pub fn write_bytes_to_file_sync(path: &str, data: &[u8]) -> Result<(), io::Error> {
    fs::write(path, data)
}