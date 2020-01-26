# weep

This crate provides parser function for Windows Portable Executable (PE) File.

## Usage

Add this to your `Cargo.toml`

```toml
[dependencies]
weep = "0.1"
```

## Example

```rust
use windows_executable_parser::Container;

fn main() -> Result<(), failure::Error> {
  let path = Path::new("./path/to/windows/executable.dll");
  let container = Container::create(&path)?;
  container.parse()?;

  // You can access all of properties
  println!("{}", container.dos_container().unwrap().is_windows_executable()); // => true
}
```
