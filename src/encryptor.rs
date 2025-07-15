// Encryption
mod ecc_core;
use ecc_core::*;

use std::process;
use std::io;
use std::path::Path;
use num_bigint::BigUint;
use num_traits::Num;
use rand::{rngs::OsRng, TryRngCore};
use hex;
use cipher::{KeyIvInit, block_padding::Pkcs7, BlockEncryptMut};
use aes::Aes256;
use cbc::Encryptor;
use hkdf::Hkdf;
use sha2::Sha256;


// main 실행 함수. 코드가 실행되면 이 함수가 실행됨.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Select:\n1. Random Integer Generator\n2. Public Key Generator\n3. Encryptor\n");
    let mut initial_input = String::new();
    io::stdin().read_line(&mut initial_input).unwrap();
    initial_input = initial_input.trim().to_owned();
    if &initial_input == "1" { // 개인키 생성
        rand_generator()?;
    } else if &initial_input == "2" { // 공개키 생성
        pub_generator()?;
    } else if &initial_input == "3" { // 암호화
        encryptor()?;
    } else {
        eprintln!("Invalid Input. Terminating Program..");
        process::exit(1);
    }
    Ok(())
}

fn rand_generator() -> Result<(), Box<dyn std::error::Error>> {
    let pk = SECP256K1_CURVE.generate_private_key();
    println!("You Private Key: {}", hex::encode(&pk.to_bytes_be()));
    Ok(())
}

fn pub_generator() -> Result<(), Box<dyn std::error::Error>> {
    println!("Enter your Private Key: ");
    let mut private_key = String::new();
    io::stdin().read_line(&mut private_key).unwrap();
    private_key = private_key.trim().to_owned();
    let private_key_biguint = BigUint::from_str_radix(&private_key, 16)?;
    let public_key = SECP256K1_CURVE.generate_public_key(&private_key_biguint);
    match public_key {
        Point::Coordinates {x, y} => {
            let x_hex = hex::encode(&x.value.to_bytes_be());
            println!("X Coordinate of your Public Key: {}", x_hex);
            let y_hex = hex::encode(&y.value.to_bytes_be());
            println!("Y Coordinate of your Public Key: {}", y_hex);
        }
        Point::Identity => {
            println!("Error: Point at Infinity.");
        }
    }
    Ok(())
}

// AES-256 암호화 함수. 파일 데이터를 암호화함.
fn encryptor() -> Result<(), Box<dyn std::error::Error>> {
    println!("Enter your Private Key: ");
    let mut private_key = String::new();
    io::stdin().read_line(&mut private_key).unwrap();
    private_key = private_key.trim().to_owned();
    let decoded_bytes = hex::decode(private_key)
        .map_err(|e| format!("Wrong Hex String: {}", e));

    let private_key_bytes:[u8;32] = decoded_bytes?.try_into()
        .expect("Vector is not correct.");
    let private_key_bytes_biguint = BigUint::from_bytes_be(&private_key_bytes);

    println!("Enter the X Coordinate of Other's Public Key: ");
    let mut public_key_x = String::new();
    io::stdin().read_line(&mut public_key_x).unwrap();
    public_key_x = public_key_x.trim().to_owned();
    println!("Enter the Y Coordinate of Other's Public Key: ");
    let mut public_key_y = String::new();
    io::stdin().read_line(&mut public_key_y).unwrap();
    public_key_y = public_key_y.trim().to_owned();

    let public_key_x_biguint = BigUint::from_str_radix(&public_key_x, 16)?;
    let public_key_y_biguint = BigUint::from_str_radix(&public_key_y, 16)?;

    let public_key_point = Point::Coordinates {
        x: FieldElement::new(public_key_x_biguint, SECP256K1_CURVE.p.clone()),
        y: FieldElement::new(public_key_y_biguint, SECP256K1_CURVE.p.clone())
    };

    let shared_secret = SECP256K1_CURVE.ecdh_derive_shared_secret(&private_key_bytes_biguint, &public_key_point);

    let salt: [u8;8] = [0; 8];
    let hk = Hkdf::<Sha256>::new(Some(&salt[..]), &shared_secret);
    let mut aes_key = [0u8;32];
    hk.expand(b"", &mut aes_key)
        .map_err(|e| e.to_string())?;

    // // 비밀 키를 생성함.
    // let mut key_bytes = [0u8; KEY_SIZE];
    // OsRng.try_fill_bytes(&mut key_bytes)?;

    // 초기화 벡터를 생성함.
    let mut iv_bytes = [0u8; BLOCK_SIZE];
    OsRng.try_fill_bytes(&mut iv_bytes)?;

    let mut file_temp_path = String::new();
    println!("Enter the File Path: ");
    io::stdin().read_line(&mut file_temp_path).unwrap();
    let file_original_path_str = file_temp_path.trim().trim_matches('\'');
    let file_original_path = Path::new(file_original_path_str);
    let plain_bytes = read_file_to_bytes_sync(file_original_path_str)?;

    let buffer_len = plain_bytes.len() + BLOCK_SIZE;
    let mut buffer = vec![0u8; buffer_len];
    buffer[..plain_bytes.len()].copy_from_slice(&plain_bytes);

    let cipher = Encryptor::<Aes256>::new(&aes_key.into(), &iv_bytes.into());

    let ciphertext_bytes = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, plain_bytes.len())
        .map_err(|e| format!("Encryption Error: {:?}", e))?;

    // println!("\n생성된 암호문 (Hex, without IV): {}", hex::encode(ciphertext_bytes));
    println!("암호문 길이 (패딩 포함): {} 바이트", ciphertext_bytes.len());
    // println!("비밀 키: {}", hex::encode(&aes_key));
    // println!("IV: {}", hex::encode(&iv_bytes));

    let mut encrypted_file_content = iv_bytes.to_vec();
    encrypted_file_content.extend_from_slice(ciphertext_bytes);

    // println!("IV + 암호문: {}", hex::encode(&encrypted_file_content));

    let output_file_name = format!("{}.locked", file_original_path.file_name().unwrap().to_string_lossy());
    let output_file_path = file_original_path.with_file_name(output_file_name);

    write_bytes_to_file_sync(output_file_path.to_str().unwrap(), &encrypted_file_content)?;

    println!("Encryption Complete.");


    Ok(())
}