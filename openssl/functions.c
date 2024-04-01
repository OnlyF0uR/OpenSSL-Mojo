#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

char *sha224(const char *str, int length)
{
  unsigned char hash[SHA224_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha224();                       // Get SHA-224 message digest
  mdctx = EVP_MD_CTX_new();                // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL);      // Initialize digest calculation context
  EVP_DigestUpdate(mdctx, str, length);    // Update digest calculation with input data
  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context

  char *output = (char *)malloc(SHA224_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA224_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha224_file(const char *str, int length)
{
  FILE *file = fopen(str, "rb");
  if (file == NULL)
  {
    return NULL; // File opening failed
  }

  unsigned char hash[SHA224_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha224();                  // Get SHA-224 message digest
  mdctx = EVP_MD_CTX_new();           // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL); // Initialize digest calculation context

  // Read file in chunks and update digest calculation with each chunk
  unsigned char buffer[1024];
  size_t bytes;
  while ((bytes = fread(buffer, 1, 1024, file)) != 0)
  {
    EVP_DigestUpdate(mdctx, buffer, bytes);
  }

  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context
  fclose(file);           // Close the file

  char *output = (char *)malloc(SHA224_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA224_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA224_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha256(const char *str, int length)
{
  unsigned char hash[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha256();                       // Get SHA-256 message digest
  mdctx = EVP_MD_CTX_new();                // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL);      // Initialize digest calculation context
  EVP_DigestUpdate(mdctx, str, length);    // Update digest calculation with input data
  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context

  char *output = (char *)malloc(SHA256_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA256_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha256_file(const char *path)
{
  FILE *file = fopen(path, "rb");
  if (file == NULL)
  {
    return NULL; // File opening failed
  }

  unsigned char hash[SHA256_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha256();                  // Get SHA-256 message digest
  mdctx = EVP_MD_CTX_new();           // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL); // Initialize digest calculation context

  // Read file in chunks and update digest calculation with each chunk
  unsigned char buffer[1024];
  size_t bytes;
  while ((bytes = fread(buffer, 1, 1024, file)) != 0)
  {
    EVP_DigestUpdate(mdctx, buffer, bytes);
  }

  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context
  fclose(file);           // Close the file

  char *output = (char *)malloc(SHA256_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA256_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha384(const char *str, int length)
{
  unsigned char hash[SHA384_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha384();                       // Get SHA-384 message digest
  mdctx = EVP_MD_CTX_new();                // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL);      // Initialize digest calculation context
  EVP_DigestUpdate(mdctx, str, length);    // Update digest calculation with input data
  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context

  char *output = (char *)malloc(SHA384_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA384_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha384_file(const char *str, int length)
{
  FILE *file = fopen(str, "rb");
  if (file == NULL)
  {
    return NULL; // File opening failed
  }

  unsigned char hash[SHA384_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha384();                  // Get SHA-384 message digest
  mdctx = EVP_MD_CTX_new();           // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL); // Initialize digest calculation context

  // Read file in chunks and update digest calculation with each chunk
  unsigned char buffer[1024];
  size_t bytes;
  while ((bytes = fread(buffer, 1, 1024, file)) != 0)
  {
    EVP_DigestUpdate(mdctx, buffer, bytes);
  }

  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context
  fclose(file);           // Close the file

  char *output = (char *)malloc(SHA384_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA384_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha512(const char *str, int length)
{
  unsigned char hash[SHA512_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha512();                       // Get SHA-512 message digest
  mdctx = EVP_MD_CTX_new();                // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL);      // Initialize digest calculation context
  EVP_DigestUpdate(mdctx, str, length);    // Update digest calculation with input data
  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context

  char *output = (char *)malloc(SHA512_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA512_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}

char *sha512_file(const char *str, int length)
{
  FILE *file = fopen(str, "rb");
  if (file == NULL)
  {
    return NULL; // File opening failed
  }

  unsigned char hash[SHA512_DIGEST_LENGTH];
  EVP_MD_CTX *mdctx;
  const EVP_MD *md;
  int mdlen;

  md = EVP_sha512();                  // Get SHA-512 message digest
  mdctx = EVP_MD_CTX_new();           // Create context for digest calculation
  EVP_DigestInit_ex(mdctx, md, NULL); // Initialize digest calculation context

  // Read file in chunks and update digest calculation with each chunk
  unsigned char buffer[1024];
  size_t bytes;
  while ((bytes = fread(buffer, 1, 1024, file)) != 0)
  {
    EVP_DigestUpdate(mdctx, buffer, bytes);
  }

  EVP_DigestFinal_ex(mdctx, hash, &mdlen); // Finalize digest calculation and obtain result

  EVP_MD_CTX_free(mdctx); // Free the digest calculation context
  fclose(file);           // Close the file

  char *output = (char *)malloc(SHA512_DIGEST_LENGTH * 2 + 1);
  if (output == NULL)
  {
    return NULL; // Allocation failed
  }

  // Convert binary hash to hexadecimal string
  for (int i = 0; i < SHA512_DIGEST_LENGTH; i++)
  {
    sprintf(output + (i * 2), "%02x", hash[i]);
  }

  output[SHA512_DIGEST_LENGTH * 2] = '\0'; // Null-terminate the string
  return output;
}