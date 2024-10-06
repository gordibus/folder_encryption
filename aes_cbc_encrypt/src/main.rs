use aes::Aes256;
use block_modes::{BlockMode, Cbc};
use block_modes::block_padding::Pkcs7;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use rand::Rng;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use walkdir::WalkDir;

// AES-CBC type definition
type Aes256Cbc = Cbc<Aes256, Pkcs7>;

const PBKDF2_ITERATIONS: u32 = 100_000;
const KEY_SIZE: usize = 32; // AES-256 uses a 32-byte key
const IV_SIZE: usize = 16;  // AES-CBC uses a 16-byte IV

fn main() {
    // Get the folder path from the user
    println!("Enter the path of the folder to encrypt:");
    let mut folder_path = String::new();
    std::io::stdin().read_line(&mut folder_path).unwrap();
    let folder_path = folder_path.trim();

    // Get the secret phrase from the user
    println!("Enter your secret phrase:");
    let mut secret_phrase = String::new();
    std::io::stdin().read_line(&mut secret_phrase).unwrap();
    let secret_phrase = secret_phrase.trim();

    // Generate a key from the secret phrase using PBKDF2
    let salt = generate_salt();
    let key = derive_key_from_passphrase(secret_phrase, &salt);

    // Create a new folder to store encrypted files
    let encrypted_folder = format!("{}_encrypted", folder_path);
    fs::create_dir_all(&encrypted_folder).expect("Failed to create encrypted folder.");

    // Iterate over the folder and encrypt each file
    for entry in WalkDir::new(folder_path) {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_file() {
            encrypt_file(path, &encrypted_folder, &key);
        }
    }

    println!("Encryption completed. Encrypted files are saved in '{}'", encrypted_folder);
}

// Generate a random salt for PBKDF2
fn generate_salt() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    rng.fill(&mut salt);
    salt
}

// Derive the AES key from the passphrase using PBKDF2
fn derive_key_from_passphrase(passphrase: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let mut key = [0u8; KEY_SIZE];
    pbkdf2::<Sha256>(passphrase.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

// Encrypt a file using AES-256-CBC
fn encrypt_file(file_path: &Path, output_folder: &str, key: &[u8]) {
    // Read the file content
    let mut file = File::open(file_path).expect("Failed to open file.");
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).expect("Failed to read file.");

    // Generate a random IV
    let iv = generate_iv();

    // Create an AES-CBC cipher instance
    let cipher = Aes256Cbc::new_from_slices(key, &iv).expect("Failed to create AES cipher.");

    // Encrypt the file content
    let ciphertext = cipher.encrypt_vec(&buffer);

    // Write the salt, IV, and ciphertext to the encrypted file
    let encrypted_file_path = Path::new(output_folder).join(file_path.file_name().unwrap());
    let mut encrypted_file = File::create(encrypted_file_path).expect("Failed to create encrypted file.");
    
    encrypted_file.write_all(&iv).expect("Failed to write IV.");
    encrypted_file.write_all(&ciphertext).expect("Failed to write encrypted data.");
}

// Generate a random IV for AES-CBC
fn generate_iv() -> [u8; IV_SIZE] {
    let mut rng = rand::thread_rng();
    let mut iv = [0u8; IV_SIZE];
    rng.fill(&mut iv);
    iv
}
