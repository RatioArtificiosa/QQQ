use qqq_fuzz::CORPUS;
use qqq_cap::manifest::Manifest;

fn main() {
    for (i, input) in CORPUS.iter().enumerate() {
        match Manifest::parse(input) {
            Ok(_) => println!("[{i:2}] PARSE  {}", input.replace('\n', "\\n")),
            Err(e) => println!("[{i:2}] REJECT {:<60} | {}", input.replace('\n', "\\n"), e),
        }
    }
}
