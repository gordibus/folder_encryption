use aes::Aes256;
use aes::cipher::{KeyIvInit, BlockEncryptMut, block_padding::Pkcs7};
use rand::Rng;
use sha2::{Sha256, Digest};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;

// AES-256-CBC encryption type
type Aes256CbcEnc = cbc::Encryptor<Aes256>;

const KEY_SIZE: usize = 32; // 256-bit key size
const IV_SIZE: usize = 16;  // 128-bit IV size (for AES)

fn main() {
    // Get the folder path from the user
    println!("Enter the folder path:");
    let mut folder_path = String::new();
    std::io::stdin().read_line(&mut folder_path).unwrap();
    let folder_path = folder_path.trim();

    // Get the secret phrase from the user
    println!("Enter the passphrase:");
    let mut passphrase = String::new();
    std::io::stdin().read_line(&mut passphrase).unwrap();
    let passphrase = passphrase.trim();

    // Derive the key from the passphrase using SHA-256
    let key = derive_key(passphrase);

    // Create an output folder for encrypted files
    let encrypted_folder = format!("{}_encrypted", folder_path);
    fs::create_dir_all(&encrypted_folder).expect("Failed to create the output folder.");

    // Encrypt each file in the folder
    for entry in fs::read_dir(folder_path).expect("Failed to read the folder.") {
        let entry = entry.expect("Failed to read the directory entry.");
        let path = entry.path();

        if path.is_file() {
            encrypt_file(&path, &encrypted_folder, &key);
        }
    }

    println!("Files encrypted and saved to '{}'", encrypted_folder);
}

// Derive a 32-byte key using SHA-256 on the passphrase
fn derive_key(passphrase: &str) -> [u8; KEY_SIZE] {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let result = hasher.finalize();
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&result[..KEY_SIZE]);
    key
}

// Encrypt a single file
fn encrypt_file(file_path: &Path, output_folder: &str, key: &[u8; KEY_SIZE]) {
    // Read the file into memory
    let mut file = File::open(file_path).expect("Failed to open the file.");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read the file.");

    // Generate a random 16-byte IV
    let iv = generate_iv();

    // Create the AES-256-CBC encryptor with the key and IV
    let cipher = Aes256CbcEnc::new(key.into(), &iv.into());

    // Encrypt the file with PKCS7 padding
    let mut ciphertext = buffer.clone(); // Use a mutable copy of the buffer
    cipher.encrypt_padded_mut::<Pkcs7>(&mut ciphertext, buffer.len()).expect("Failed to encrypt.");

    // Write the IV + encrypted content to the output file
    let encrypted_file_path = Path::new(output_folder).join(file_path.file_name().unwrap());
    let mut encrypted_file = File::create(encrypted_file_path).expect("Failed to create the encrypted file.");
    encrypted_file.write_all(&iv).expect("Failed to write the IV.");
    encrypted_file.write_all(&ciphertext).expect("Failed to write the ciphertext.");
}

// Generate a random 16-byte IV
fn generate_iv() -> [u8; IV_SIZE] {
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; IV_SIZE];
    rng.fill(&mut iv);
    iv
}

