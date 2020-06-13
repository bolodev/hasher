use argparse::{ArgumentParser, Store, StoreTrue};
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
    let mut json_out = false;
    
    {  // this block copied from argparse example
        let mut ap = ArgumentParser::new();
        ap.set_description("Hash input file to stdio");
        ap.refer(&mut input).add_option(&["-f", "--file"], Store, "Input file");
        ap.refer(&mut directory).add_option(&["-d", "--dir"], Store, "Input directory");
        ap.refer(&mut buffer_size).add_option(&["-b", "--buffer"], Store, "Buffer size (bytes)");
        ap.refer(&mut json_out).add_option(&["-j", "--json"], StoreTrue, "JSON output");
        ap.parse_args_or_exit();
    }

    if &input != "" {
        let hashes: Hashes = hash_file(&input, buffer_size);
        if json_out {
            print_hash_to_json(hashes);
        }
        else {
            print_hash_to_line(hashes);
        }
    }
    
    if &directory != "" {
        if !json_out {
            println!("Input directory:  {}", &directory);
        }        
        hash_directory(&directory, buffer_size, json_out);
    }

    if !json_out {
        let elapsed = time::now() - started;
        println!("Time elasped: {}", elapsed);
    }

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
// Print the the hash results to stdio
//
fn print_hash_to_line(mut hash_results: Hashes) {
    println!("File:   {}", hash_results.file_name);
    println!("Bytes:  {}", hash_results.file_size);
    println!("MD5:    {}", hash_results.md5.result_str());
    println!("SHA1:   {}", hash_results.sha1.result_str());
    println!("SHA256: {}", hash_results.sha256.result_str());
    println!("SHA512: {}", hash_results.sha512.result_str());
    println!("");
}

//
// Print JSON formatted hash results to stdio
//
fn print_hash_to_json(mut hash_results: Hashes) {
    let mut file_name = hash_results.file_name;
    if file_name.contains("\\") {
        file_name = file_name.replace("\\", "\\\\");
    }

    println!("{{\"file_name\": \"{}\", \"file_bytes\": {}, \"file_md5\": \"{}\", \"file_sha1\": \"{}\", \"file_sha256\": \"{}\", \"file_512\": \"{}\"}}", 
        file_name, 
        hash_results.file_size,
        hash_results.md5.result_str(),
        hash_results.sha1.result_str(),
        hash_results.sha256.result_str(),
        hash_results.sha512.result_str()
    );
}

//
// Recurse through a directory structure
//
fn hash_directory(input: &str, buffer_size: usize, to_json: bool) {

    for entry in WalkDir::new(input) {
        match entry {
            Ok(entry) => {
                let foo = entry.path();
                if !foo.is_dir() {
                    let hashes = hash_file(foo.to_str().unwrap(), buffer_size);
                    if to_json {
                        print_hash_to_json(hashes)
                    }
                    else {
                        print_hash_to_line(hashes);
                    }
                }
            },
            Err(error) => println!("[ERROR] {:?}", error),
        }
    }

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
