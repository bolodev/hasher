use argparse::{ArgumentParser, Store};
use crypto::md5::Md5;
use crypto::sha1::Sha1;
use crypto::sha2::{Sha256, Sha512};
use crypto::digest::Digest;
use std::io::BufReader;
use std::io::prelude::*;
use std::io::ErrorKind;
use std::fs::File;
use time;
use walkdir::WalkDir;

//
// Main - entrypoint
//
fn main() {

    let started = time::now();
    let mut input = "".to_string();
    let mut directory = "".to_string();
    let mut buffer_size = 512; // Default 512bytes
    
    {  // this block copied from argparse example
        let mut ap = ArgumentParser::new();
        ap.set_description("Hash input file to stdio");
        ap.refer(&mut input).add_option(&["-f", "--file"], Store, "Input file");
        ap.refer(&mut directory).add_option(&["-d", "--dir"], Store, "Input directory");
        ap.refer(&mut buffer_size).add_option(&["-b", "--buffer"], Store, "Buffer size (bytes)");
        ap.parse_args_or_exit();
    }

    if &input != "" {
        println!("Input file:  {}", &input);
        let mut hashes: Hashes = hash_file(&input, buffer_size);
        println!("Bytes:  {}", &hashes.file_size);
        println!("MD5:    {}", &hashes.md5.result_str());
        println!("SHA1:   {}", &hashes.sha1.result_str());
        println!("SHA256: {}", &hashes.sha256.result_str());
        println!("SHA512: {}", &hashes.sha512.result_str());
        println!("");
    }
    
    if &directory != "" {
        println!("Input directory:  {}", &directory);
        let hashes = hash_directory(&directory, buffer_size);
        for mut hash_struct in hashes {
            println!("Filename: {}", hash_struct.file_name);
            println!("Bytes:    {}", hash_struct.file_size);
            println!("MD5:      {}", hash_struct.md5.result_str());
            println!("SHA1:     {}", hash_struct.sha1.result_str());
            println!("SHA256:   {}", hash_struct.sha256.result_str());
            println!("SHA512:   {}", hash_struct.sha512.result_str());
            println!("");
        }
    }

    let elapsed = time::now() - started;
    println!("Time elasped: {}", elapsed);

}

///
/// Struct to hold hash digests
/// 
struct Hashes {
    file_name: String,
    file_size: u64,
    md5: Md5,
    sha1: Sha1,
    sha256: Sha256,
    sha512: Sha512,
}

//
// Recurse through a directory structure
//
fn hash_directory(input: &str, buffer_size: usize) -> Vec<Hashes> {
    let mut hashes: Vec<Hashes> = Vec::new();

    for entry in WalkDir::new(input) {
        match entry {
            Ok(entry) => {
                let foo = entry.path();
                if !foo.is_dir() {
                   hashes.push(hash_file(foo.to_str().unwrap(), buffer_size));
                }
            },
            Err(error) => println!("[ERROR] {:?}", error),
        }
    }

    hashes
}

///
/// Hash a file, return Hashes struct
/// 
fn hash_file(input: &str, buffer_size: usize) -> Hashes{

    let input_file = File::open(input);
    let mut file_length = 0;

    let input_file = match input_file {
        Ok(file) => {
            file_length = file.metadata().unwrap().len();
            file
        },
        Err(error) => match error.kind() {
            ErrorKind::NotFound => match File::open(input) {
                Ok(fc) => fc,
                Err(e) => panic!("[ERROR] Tried to open file but there was a problem: {:?}", e),
            },
            other_error => panic!("[ERROR] There was a problem opening the file: {:?}", other_error),
        },
    };

    let mut md5_digest = Md5::new();
    let mut sha1_digest = Sha1::new();
    let mut sha256_digest = Sha256::new();
    let mut sha512_digest = Sha512::new();

    // const BUF_SIZE: usize = 512;
    let mut reader = BufReader::with_capacity(buffer_size, &input_file);
    loop {
        let length = {
            match reader.fill_buf() {
                Ok(read_bytes) => {
                    md5_digest.input(read_bytes);
                    sha1_digest.input(read_bytes);
                    sha256_digest.input(read_bytes);
                    sha512_digest.input(read_bytes);
                    read_bytes.len()
                },
                Err(e) => panic!("Error reading file: {}", e),
            }
        };
        if length == 0 {
            break;
        }
        reader.consume(length);
    }

    // Return digests
    Hashes{
        file_name: input.to_string(),
        file_size: file_length,
        md5: md5_digest,
        sha1: sha1_digest,
        sha256: sha256_digest,
        sha512: sha512_digest,
    }
    
}
