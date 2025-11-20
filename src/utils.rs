use anyhow::{Context, Result};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use tokio::signal;

pub fn read_lines<P>(filename: P) -> Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(&filename).with_context(|| format!("Failed to open file: {:?}", filename.as_ref()))?;
    let lines = io::BufReader::new(file).lines();
    let mut result = Vec::new();
    for line in lines {
        let line = line?;
        if !line.trim().is_empty() {
            result.push(line.trim().to_string());
        }
    }
    Ok(result)
}

