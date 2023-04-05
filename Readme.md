# **`Encodkit`**

Fast encoder/decoder toolkit for power-users.

## `Features`

- Fast encoder/Decoder for
  - Bat 85 - 91
  - Base64
- Converts file or folder to .bat via makecab.exe compression

## Note

Keep in mind that encoding a file to a string will increase its size, as the original binary data is being converted to a text representation.

This may not be practical for very large files, as it may result in a significantly larger string and

may consume more memory. In these cases, it may be more efficient to use a different approach,

such as streaming the file in small chunks and encoding each chunk separately.
